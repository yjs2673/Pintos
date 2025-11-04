#include "threads/thread.h"
#include <debug.h>
#include <stddef.h>
#include <random.h>
#include <stdio.h>
#include <string.h>
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/intr-stubs.h"
#include "threads/palloc.h"
#include "threads/switch.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#ifdef USERPROG
#include "userprog/process.h"
#endif
#include "devices/timer.h"
#include "threads/fixed-point.h"

/* Random value for struct thread's `magic' member.
   Used to detect stack overflow.  See the big comment at the top
   of thread.h for details. */
#define THREAD_MAGIC 0xcd6abf4b

/* List of processes in THREAD_READY state, that is, processes
   that are ready to run but not actually running. */
static struct list ready_list[PRI_MAX + 1];
static int load_avg;

/* List of processes in BLOCKED state */
static struct list sleep_list;

/* List of all processes.  Processes are added to this list
   when they are first scheduled and removed when they exit. */
static struct list all_list;

/* Idle thread. */
static struct thread *idle_thread;

/* Initial thread, the thread running init.c:main(). */
static struct thread *initial_thread;

/* Lock used by allocate_tid(). */
static struct lock tid_lock;

/* Stack frame for kernel_thread(). */
struct kernel_thread_frame 
  {
    void *eip;                  /* Return address. */
    thread_func *function;      /* Function to call. */
    void *aux;                  /* Auxiliary data for function. */
  };

/* Statistics. */
static long long idle_ticks;    /* # of timer ticks spent idle. */
static long long kernel_ticks;  /* # of timer ticks in kernel threads. */
static long long user_ticks;    /* # of timer ticks in user programs. */

/* Scheduling. */
#define TIME_SLICE 4            /* # of timer ticks to give each thread. */
static unsigned thread_ticks;   /* # of timer ticks since last yield. */

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
bool thread_mlfqs;

bool thread_prior_aging;
void thread_aging (void);

static void kernel_thread (thread_func *, void *aux);

static void idle (void *aux UNUSED);
static struct thread *running_thread (void);
static struct thread *next_thread_to_run (void);
static void init_thread (struct thread *, const char *name, int priority);
static bool is_thread (struct thread *) UNUSED;
static void *alloc_frame (struct thread *, size_t size);
static void schedule (void);
void thread_schedule_tail (struct thread *prev);
static tid_t allocate_tid (void);

bool
thread_priority_greater (const struct list_elem *a,
                         const struct list_elem *b,
                         void *aux UNUSED)
{
  const struct thread *ta = list_entry (a, struct thread, elem);
  const struct thread *tb = list_entry (b, struct thread, elem);
  return ta->priority > tb->priority;
}

void
thread_check_preemption (void)
{
  /* ready_list가 비어있으면 선점할 스레드가 없음 */
  if (list_empty (&ready_list)) return;
  
  /* 현재 스레드가 idle 스레드이거나 인터럽트 컨텍스트에서는 yield 불가 */
  if (thread_current () == idle_thread || intr_context ()) return;

  /* ready_list의 맨 앞(가장 높은 우선순위) 스레드와 비교 */
  struct thread *highest_ready = list_entry (list_front (&ready_list), struct thread, elem);
  if (thread_current ()->priority < highest_ready->priority) thread_yield ();
}

/* Initializes the threading system by transforming the code
   that's currently running into a thread.  This can't work in
   general and it is possible in this case only because loader.S
   was careful to put the bottom of the stack at a page boundary.

   Also initializes the run queue and the tid lock.

   After calling this function, be sure to initialize the page
   allocator before trying to create any threads with
   thread_create().

   It is not safe to call thread_current() until this function
   finishes. */
void
thread_init (void) 
{
  ASSERT (intr_get_level () == INTR_OFF);

  lock_init (&tid_lock);

  for (int i = 0; i <= PRI_MAX; i++) list_init (&ready_list[i]);
  load_avg = INT_TO_FP (0);

  list_init (&all_list);
  list_init (&sleep_list); // init BLOCKED processes list

  /* Set up a thread structure for the running thread. */
  initial_thread = running_thread ();
  init_thread (initial_thread, "main", PRI_DEFAULT);
  initial_thread->status = THREAD_RUNNING;
  initial_thread->tid = allocate_tid ();

  initial_thread->nice = 0;
  initial_thread->recent_cpu = INT_TO_FP (0);
}

/* Starts preemptive thread scheduling by enabling interrupts.
   Also creates the idle thread. */
void
thread_start (void) 
{
  /* Create the idle thread. */
  struct semaphore idle_started;
  sema_init (&idle_started, 0);
  thread_create ("idle", PRI_MIN, idle, &idle_started);

  /* Start preemptive thread scheduling. */
  intr_enable ();

  /* Wait for the idle thread to initialize idle_thread. */
  sema_down (&idle_started);
}

/* Called by the timer interrupt handler at each timer tick.
   Thus, this function runs in an external interrupt context. */
void
thread_tick (void) 
{
  struct thread *t = thread_current ();

  /* Update statistics. */
  if (t == idle_thread)
    idle_ticks++;
#ifdef USERPROG
  else if (t->pagedir != NULL)
    user_ticks++;
#endif
  else
    kernel_ticks++;

  if (thread_mlfqs)
  {
    /* 1. 매 틱마다 recent_cpu 1 증가 */
    mlfqs_increment_recent_cpu ();
      
    /* 2. 1초마다 load_avg와 모든 recent_cpu 갱신 */
    if (timer_ticks () % TIMER_FREQ == 0)
    {
      mlfqs_update_load_avg ();
          
      /* 모든 스레드의 recent_cpu 갱신 */
      struct list_elem *e;
      for (e = list_begin (&all_list); e != list_end (&all_list); e = list_next (e))
      {
        mlfqs_calculate_recent_cpu (list_entry (e, struct thread, allelem));
      }
    }
        
    /* 3. 4틱마다 모든 priority 갱신 */
    if (timer_ticks () % TIME_SLICE == 0)
    {
      struct list_elem *e;
      for (e = list_begin (&all_list); e != list_end (&all_list); e = list_next (e))
      {
        mlfqs_calculate_priority (list_entry (e, struct thread, allelem));
      }
    }
  }

  /* Enforce preemption. */
  if (++thread_ticks >= TIME_SLICE)
    intr_yield_on_return ();

  /* 매 틱마다 깨어날 스레드가 있는지 검사 */
  thread_wake_up ();

  if (thread_prior_aging == true) thread_aging ();

  if (thread_mlfqs)
  {
  /* MLFQS의 선점 확인: ready_list 중 현재 스레드보다 높은 우선순위 큐에 스레드가 있는지 확인 */
    for (int i = PRI_MAX; i > thread_current ()->priority; i--)
    {
      if (!list_empty (&ready_list[i]))
      {
        intr_yield_on_return ();
        break;
      }
    }
  }
  else
  {
    /* 기존 Priority Scheduler 선점 로직 */
    if (!list_empty(&ready_list) &&
        thread_current ()->priority < 
        list_entry(list_front(&ready_list), struct thread, elem)->priority)
    {
      intr_yield_on_return ();
    }
  }
}

/* Prints thread statistics. */
void
thread_print_stats (void) 
{
  printf ("Thread: %lld idle ticks, %lld kernel ticks, %lld user ticks\n",
          idle_ticks, kernel_ticks, user_ticks);
}

/* Creates a new kernel thread named NAME with the given initial
   PRIORITY, which executes FUNCTION passing AUX as the argument,
   and adds it to the ready queue.  Returns the thread identifier
   for the new thread, or TID_ERROR if creation fails.

   If thread_start() has been called, then the new thread may be
   scheduled before thread_create() returns.  It could even exit
   before thread_create() returns.  Contrariwise, the original
   thread may run for any amount of time before the new thread is
   scheduled.  Use a semaphore or some other form of
   synchronization if you need to ensure ordering.

   The code provided sets the new thread's `priority' member to
   PRIORITY, but no actual priority scheduling is implemented.
   Priority scheduling is the goal of Problem 1-3. */
tid_t
thread_create (const char *name, int priority,
               thread_func *function, void *aux) 
{
  struct thread *t;
  struct kernel_thread_frame *kf;
  struct switch_entry_frame *ef;
  struct switch_threads_frame *sf;
  tid_t tid;

  ASSERT (function != NULL);

  /* Allocate thread. */
  t = palloc_get_page (PAL_ZERO);
  if (t == NULL)
    return TID_ERROR;

  /* Initialize thread. */
  init_thread (t, name, priority);
  tid = t->tid = allocate_tid ();

  /* Stack frame for kernel_thread(). */
  kf = alloc_frame (t, sizeof *kf);
  kf->eip = NULL;
  kf->function = function;
  kf->aux = aux;

  /* Stack frame for switch_entry(). */
  ef = alloc_frame (t, sizeof *ef);
  ef->eip = (void (*) (void)) kernel_thread;

  /* Stack frame for switch_threads(). */
  sf = alloc_frame (t, sizeof *sf);
  sf->eip = switch_entry;
  sf->ebp = 0;

  /* Add to run queue. */
  thread_unblock (t);

  /* 새 스레드의 우선순위가 현재 스레드보다 높으면 CPU 양보 */
  if (t->priority > thread_current ()->priority) thread_yield ();

  return tid;
}

/* Puts the current thread to sleep.  It will not be scheduled
   again until awoken by thread_unblock().

   This function must be called with interrupts turned off.  It
   is usually a better idea to use one of the synchronization
   primitives in synch.h. */
void
thread_block (void) 
{
  ASSERT (!intr_context ());
  ASSERT (intr_get_level () == INTR_OFF);

  thread_current ()->status = THREAD_BLOCKED;
  schedule ();
}

/* Transitions a blocked thread T to the ready-to-run state.
   This is an error if T is not blocked.  (Use thread_yield() to
   make the running thread ready.)

   This function does not preempt the running thread.  This can
   be important: if the caller had disabled interrupts itself,
   it may expect that it can atomically unblock a thread and
   update other data. */
void
thread_unblock (struct thread *t) 
{
  enum intr_level old_level;

  ASSERT (is_thread (t));

  old_level = intr_disable ();
  ASSERT (t->status == THREAD_BLOCKED);

  if (thread_mlfqs) list_push_back (&ready_list[t->priority], &t->elem);
  else list_insert_ordered (&ready_list, &t->elem, thread_priority_greater, NULL);
  
  t->status = THREAD_READY;
  intr_set_level (old_level);
}

/* Returns the name of the running thread. */
const char *
thread_name (void) 
{
  return thread_current ()->name;
}

/* Returns the running thread.
   This is running_thread() plus a couple of sanity checks.
   See the big comment at the top of thread.h for details. */
struct thread *
thread_current (void) 
{
  struct thread *t = running_thread ();
  
  /* Make sure T is really a thread.
     If either of these assertions fire, then your thread may
     have overflowed its stack.  Each thread has less than 4 kB
     of stack, so a few big automatic arrays or moderate
     recursion can cause stack overflow. */
  ASSERT (is_thread (t));
  ASSERT (t->status == THREAD_RUNNING);

  return t;
}

/* Returns the running thread's tid. */
tid_t
thread_tid (void) 
{
  return thread_current ()->tid;
}

/* Deschedules the current thread and destroys it.  Never
   returns to the caller. */
void
thread_exit (void) 
{
  ASSERT (!intr_context ());

#ifdef USERPROG
  process_exit ();
#endif

  /* Remove thread from all threads list, set our status to dying,
     and schedule another process.  That process will destroy us
     when it calls thread_schedule_tail(). */
  intr_disable ();
  list_remove (&thread_current()->allelem);
  thread_current ()->status = THREAD_DYING;
  schedule ();
  NOT_REACHED ();
}

/* Yields the CPU.  The current thread is not put to sleep and
   may be scheduled again immediately at the scheduler's whim. */
void
thread_yield (void) 
{
  struct thread *cur = thread_current ();
  enum intr_level old_level;
  
  ASSERT (!intr_context ());

  old_level = intr_disable ();
  if (cur != idle_thread) 
  {
    if (thread_mlfqs) list_push_back (&ready_list[cur->priority], &cur->elem); 
    else list_insert_ordered (&ready_list, &cur->elem, thread_priority_greater, NULL);
  }
  cur->status = THREAD_READY;
  schedule ();
  intr_set_level (old_level);
}

/* Invoke function 'func' on all threads, passing along 'aux'.
   This function must be called with interrupts off. */
void
thread_foreach (thread_action_func *func, void *aux)
{
  struct list_elem *e;

  ASSERT (intr_get_level () == INTR_OFF);

  for (e = list_begin (&all_list); e != list_end (&all_list);
       e = list_next (e))
    {
      struct thread *t = list_entry (e, struct thread, allelem);
      func (t, aux);
    }
}

/* Sets the current thread's priority to NEW_PRIORITY. */
void
thread_set_priority (int new_priority) 
{
  /* MLFQS 스케줄러가 아닐 때만 작동 */
  if (thread_mlfqs) return;

  enum intr_level old_level = intr_disable ();
  
  struct thread *cur = thread_current ();
  cur->base_priority = new_priority;

  /* 기부받은 우선순위가 있는지 확인하여 priority update*/
  thread_recalculate_priority (cur);

  /* 우선순위가 낮아졌을 경우, ready_list의 다른 스레드보다
     우선순위가 낮아졌는지 확인하고, 그렇다면 yield */
  thread_check_preemption ();
  
  intr_set_level (old_level);
}

/* Returns the current thread's priority. */
int
thread_get_priority (void) 
{
  return thread_current ()->priority;
}

/* Sets the current thread's nice value to NICE. */
void
thread_set_nice (int nice UNUSED) 
{
  struct thread *cur = thread_current ();
  cur->nice = nice;
  
  /* nice 변경 시 즉시 priority 재계산 */
  mlfqs_calculate_priority (cur);
  
  /* 재계산 결과, 우선순위가 가장 높지 않다면 yield */
  int highest_pri = PRI_MIN;
  for (int i = PRI_MAX; i > cur->priority; i--)
  {
    if (!list_empty (&ready_list[i]))
    {
      highest_pri = i;
      break;
    }
  }
  
  if (cur->priority < highest_pri) thread_yield ();
}

/* Returns the current thread's nice value. */
int
thread_get_nice (void) 
{
  return thread_current ()->nice;
}

/* Returns 100 times the system load average. */
int
thread_get_load_avg (void) 
{
  return FP_TO_INT_ROUND (FP_MUL_INT (load_avg, 100));
}

/* Returns 100 times the current thread's recent_cpu value. */
int
thread_get_recent_cpu (void) 
{
  return FP_TO_INT_ROUND (FP_MUL_INT (thread_current ()->recent_cpu, 100));
}

/* Idle thread.  Executes when no other thread is ready to run.

   The idle thread is initially put on the ready list by
   thread_start().  It will be scheduled once initially, at which
   point it initializes idle_thread, "up"s the semaphore passed
   to it to enable thread_start() to continue, and immediately
   blocks.  After that, the idle thread never appears in the
   ready list.  It is returned by next_thread_to_run() as a
   special case when the ready list is empty. */
static void
idle (void *idle_started_ UNUSED) 
{
  struct semaphore *idle_started = idle_started_;
  idle_thread = thread_current ();
  sema_up (idle_started);

  for (;;) 
    {
      /* Let someone else run. */
      intr_disable ();
      thread_block ();

      /* Re-enable interrupts and wait for the next one.

         The `sti' instruction disables interrupts until the
         completion of the next instruction, so these two
         instructions are executed atomically.  This atomicity is
         important; otherwise, an interrupt could be handled
         between re-enabling interrupts and waiting for the next
         one to occur, wasting as much as one clock tick worth of
         time.

         See [IA32-v2a] "HLT", [IA32-v2b] "STI", and [IA32-v3a]
         7.11.1 "HLT Instruction". */
      asm volatile ("sti; hlt" : : : "memory");
    }
}

/* Function used as the basis for a kernel thread. */
static void
kernel_thread (thread_func *function, void *aux) 
{
  ASSERT (function != NULL);

  intr_enable ();       /* The scheduler runs with interrupts off. */
  function (aux);       /* Execute the thread function. */
  thread_exit ();       /* If function() returns, kill the thread. */
}

/* Returns the running thread. */
struct thread *
running_thread (void) 
{
  uint32_t *esp;

  /* Copy the CPU's stack pointer into `esp', and then round that
     down to the start of a page.  Because `struct thread' is
     always at the beginning of a page and the stack pointer is
     somewhere in the middle, this locates the curent thread. */
  asm ("mov %%esp, %0" : "=g" (esp));
  return pg_round_down (esp);
}

/* Returns true if T appears to point to a valid thread. */
static bool
is_thread (struct thread *t)
{
  return t != NULL && t->magic == THREAD_MAGIC;
}

/* Does basic initialization of T as a blocked thread named
   NAME. */
static void
init_thread (struct thread *t, const char *name, int priority)
{
  enum intr_level old_level;

  ASSERT (t != NULL);
  ASSERT (PRI_MIN <= priority && priority <= PRI_MAX);
  ASSERT (name != NULL);

  memset (t, 0, sizeof *t);
  t->status = THREAD_BLOCKED;
  strlcpy (t->name, name, sizeof t->name);
  t->stack = (uint8_t *) t + PGSIZE;
  t->priority = priority;
  t->magic = THREAD_MAGIC;

  t->base_priority = priority;
  list_init (&t->held_locks);
  t->waiting_on_lock = NULL;

  if (thread_mlfqs)
  {
    /* 부모 스레드(current)로부터 값 상속 */
    if (t != initial_thread)
    {
      t->nice = thread_current ()->nice;
      t->recent_cpu = thread_current ()->recent_cpu;
    }
  }

  old_level = intr_disable ();
  list_push_back (&all_list, &t->allelem);
  intr_set_level (old_level);

/* User Program 2*/
#ifdef USERPROG
  sema_init(&(t->lock_load), 0);
  sema_init(&(t->lock_child), 0);
  sema_init(&(t->lock_parent), 0);
  list_init(&t->child_list);
  t->exit_status = -1;
  t->exec_file = NULL;
  t->load_success = false;
  list_push_back(&(running_thread()->child_list), &(t->child_elem));
#endif
}

/* Allocates a SIZE-byte frame at the top of thread T's stack and
   returns a pointer to the frame's base. */
static void *
alloc_frame (struct thread *t, size_t size) 
{
  /* Stack data is always allocated in word-size units. */
  ASSERT (is_thread (t));
  ASSERT (size % sizeof (uint32_t) == 0);

  t->stack -= size;
  return t->stack;
}

/* Chooses and returns the next thread to be scheduled.  Should
   return a thread from the run queue, unless the run queue is
   empty.  (If the running thread can continue running, then it
   will be in the run queue.)  If the run queue is empty, return
   idle_thread. */
static struct thread *
next_thread_to_run (void) 
{
  if (thread_mlfqs)
  {  
    for (int i = PRI_MAX; i >= PRI_MIN; i--)
    {
      if (!list_empty (&ready_list[i]))
      {
        return list_entry (list_pop_front (&ready_list[i]), struct thread, elem);
      }
    }
    return idle_thread;
  }
  else
  {
    if (list_empty (&ready_list))
      return idle_thread;
    else
      return list_entry (list_pop_front (&ready_list), struct thread, elem);
  }
}

/* Completes a thread switch by activating the new thread's page
   tables, and, if the previous thread is dying, destroying it.

   At this function's invocation, we just switched from thread
   PREV, the new thread is already running, and interrupts are
   still disabled.  This function is normally invoked by
   thread_schedule() as its final action before returning, but
   the first time a thread is scheduled it is called by
   switch_entry() (see switch.S).

   It's not safe to call printf() until the thread switch is
   complete.  In practice that means that printf()s should be
   added at the end of the function.

   After this function and its caller returns, the thread switch
   is complete. */
void
thread_schedule_tail (struct thread *prev)
{
  struct thread *cur = running_thread ();
  
  ASSERT (intr_get_level () == INTR_OFF);

  /* Mark us as running. */
  cur->status = THREAD_RUNNING;

  /* Start new time slice. */
  thread_ticks = 0;

#ifdef USERPROG
  /* Activate the new address space. */
  process_activate ();
#endif

  /* If the thread we switched from is dying, destroy its struct
     thread.  This must happen late so that thread_exit() doesn't
     pull out the rug under itself.  (We don't free
     initial_thread because its memory was not obtained via
     palloc().) */
  if (prev != NULL && prev->status == THREAD_DYING && prev != initial_thread) 
    {
      ASSERT (prev != cur);
      palloc_free_page (prev);
    }
}

/* Schedules a new process.  At entry, interrupts must be off and
   the running process's state must have been changed from
   running to some other state.  This function finds another
   thread to run and switches to it.

   It's not safe to call printf() until thread_schedule_tail()
   has completed. */
static void
schedule (void) 
{
  struct thread *cur = running_thread ();
  struct thread *next = next_thread_to_run ();
  struct thread *prev = NULL;

  ASSERT (intr_get_level () == INTR_OFF);
  ASSERT (cur->status != THREAD_RUNNING);
  ASSERT (is_thread (next));

  if (cur != next)
    prev = switch_threads (cur, next);
  thread_schedule_tail (prev);
}

/* Returns a tid to use for a new thread. */
static tid_t
allocate_tid (void) 
{
  static tid_t next_tid = 1;
  tid_t tid;

  lock_acquire (&tid_lock);
  tid = next_tid++;
  lock_release (&tid_lock);

  return tid;
}


/*
 * 현재 스레드를 wakeup_tick까지 재웁니다.
 * thread_block()을 호출하므로 인터럽트가 활성화된 상태(INTR_ON)에서
 * 호출되어야 합니다.
 */
void
thread_sleep (int64_t wakeup_tick)
{
  struct thread *cur = thread_current ();
  enum intr_level old_level;

  /* 인터럽트 핸들러나 외부 인터럽트 컨텍스트에서 호출되면 안 됨 */
  ASSERT (!intr_context ());
  ASSERT (intr_get_level () == INTR_ON);

  /* 스레드 구조체에 깨어날 시간 저장 [cite: 300] */
  cur->wakeup_tick = wakeup_tick;

  /*
    sleep_list에 추가하고 스레드를 BLOCKED 상태로 만듦 [cite: 298, 299]
    이 과정은 원자적으로(atomically) 일어나야 하므로 인터럽트를 비활성화합니다.
  */
  old_level = intr_disable ();
  list_push_back (&sleep_list, &cur->elem);
  thread_block ();
  
  /* thread_wake_up() -> thread_unblock()에 의해 스레드가 다시 깨어나면
    스케줄러에 의해 이 지점부터 실행이 재개됩니다.
    원래의 인터럽트 레벨을 복원합니다.
  */
  intr_set_level (old_level);
}

/*
 * sleep_list를 순회하며 깨어날 시간이 된(wakeup_tick <= current_ticks) 모든 스레드 unblock
 * timer_interrupt -> thread_tick 문맥(INTR_OFF)에서 호출
 */
void
thread_wake_up (void)
{
  int64_t current_ticks = timer_ticks (); /* 현재 틱 시간 */
  struct list_elem *e = list_begin (&sleep_list);

  /* sleep_list를 순회 */
  while (e != list_end (&sleep_list))
  {
    struct thread *t = list_entry (e, struct thread, elem);
      
    if (t->wakeup_tick <= current_ticks) /* 스레드가 깨어날 시간인지 확인 */
    {
        struct list_elem *next = list_next (e);
        list_remove (e);      /* sleep_list에서 제거 */
        thread_unblock (t);   /* ready_list로 이동시킴 */      
        e = next;
    }
    else e = list_next (e);
  }
}

void
thread_aging (void)
{
  ASSERT (intr_get_level () == INTR_OFF);

  struct list_elem *e;
  
  /* 1. ready_list 순회 */
  for (e = list_begin (&ready_list); e != list_end (&ready_list); e = list_next (e))
  {
    struct thread *t = list_entry (e, struct thread, elem);
    if (t->base_priority < PRI_MAX)
    {
      t->base_priority++;
      /* 유효 우선순위(priority)도 갱신 */
      thread_recalculate_priority (t);
    }
  }

  /* 2. sleep_list 순회 */
  for (e = list_begin (&sleep_list); e != list_end (&sleep_list); e = list_next (e))
  {
    struct thread *t = list_entry (e, struct thread, elem);
    if (t->base_priority < PRI_MAX)
    {
      t->base_priority++;
      /* BLOCKED 상태 스레드는 당장 스케줄링 대상이 아니므로
         recalculate_priority()는 생략 가능 (unblock될 때 갱신됨)
      */
    }
  }

  /* 3. ready_list 재정렬 */
  list_sort (&ready_list, thread_priority_greater, NULL);
}

void
thread_donate_priority (struct thread *t)
{
  /* 기부는 인터럽트가 비활성화된 상태에서 호출 */
  /* lock_acquire -> sema_down 내부에서 호출 */
  
  ASSERT (intr_get_level () == INTR_OFF);

  struct thread *cur = thread_current ();
  
  /* t (lock holder)의 유효 우선순위를 현재 스레드(waiter)의 우선순위로 업데이트 */
  if (t->priority < cur->priority)
  {
    t->priority = cur->priority;
      
    /* Holder(t)가 다른 lock을 기다리고 있다면 (nested donation),
      그 lock의 holder에게도 재귀적으로 기부 */
    if (t->waiting_on_lock) thread_donate_priority (t->waiting_on_lock->holder);
  }
}

/*
 * Priority Recalculation:
 * 스레드 t가 lock을 해제(release)했거나, base_priority가 변경되었을 때 호출
 * t의 유효 우선순위(priority)를 (t->base_priority) 와 (t가 보유한 모든 lock을 기다리는 스레드들의 최대 우선순위) 중 더 큰 값으로 설정
 */
void
thread_recalculate_priority (struct thread *t)
{
  ASSERT (intr_get_level () == INTR_OFF);
  
  int max_priority = t->base_priority;

  /* 스레드가 보유한 lock이 있는지 확인 */
  if (!list_empty (&t->held_locks))
  {
    struct list_elem *e;
    for (e = list_begin (&t->held_locks); e != list_end (&t->held_locks); e = list_next (e))
    {
      struct lock *l = list_entry (e, struct lock, held_elem);
          
      /* 그 lock을 기다리는 스레드(waiters)가 있는지 확인 */
      if (!list_empty (&l->semaphore.waiters))
      {
        /* waiters 리스트는 이미 우선순위로 정렬되어 있으므로
          맨 앞의 스레드가 가장 우선순위가 높음
        */
        struct thread *waiter = list_entry (list_front (&l->semaphore.waiters), 
                                                struct thread, elem);
            
        if (waiter->priority > max_priority) max_priority = waiter->priority;
      }
    }
  }
  
  t->priority = max_priority;
}

void
mlfqs_update_load_avg (void)
{
  int ready_threads = 0;
  
  /* ready_list에 있는 스레드 수 계산 */
  for (int i = PRI_MIN; i <= PRI_MAX; i++) ready_threads += list_size (&ready_list[i]);
  /* 실행 중인 스레드 추가 (idle 제외) */
  if (thread_current () != idle_thread) ready_threads++;

  /* load_avg = (59/60) * load_avg + (1/60) * ready_threads */
  int term1 = FP_DIV_INT (FP_MUL_INT (load_avg, 59), 60);
  int term2 = FP_DIV_INT (INT_TO_FP (ready_threads), 60);
  load_avg = FP_ADD (term1, term2);
}

/* 1초마다 모든 스레드의 recent_cpu 갱신 */
void
mlfqs_calculate_recent_cpu (struct thread *t)
{
  if (t == idle_thread) return;

  /* recent_cpu = (2*load_avg)/(2*load_avg + 1) * recent_cpu + nice */
  int load_x_2 = FP_MUL_INT (load_avg, 2);
  int coeff = FP_DIV (load_x_2, FP_ADD_INT (load_x_2, 1));
  
  t->recent_cpu = FP_ADD_INT (FP_MUL (coeff, t->recent_cpu), t->nice);
}

/* 4틱마다 모든 스레드의 priority 갱신 */
void
mlfqs_calculate_priority (struct thread *t)
{
  if (t == idle_thread) return;
  
  /* priority = PRI_MAX - (recent_cpu / 4) - (nice * 2) */
  int recent_cpu_div_4 = FP_TO_INT_TRUNC (FP_DIV_INT (t->recent_cpu, 4));
  int nice_x_2 = t->nice * 2;
  
  int priority = PRI_MAX - recent_cpu_div_4 - nice_x_2;
  
  /* 우선순위가 범위를 벗어나지 않도록 조정 */
  if (priority < PRI_MIN) priority = PRI_MIN;
  if (priority > PRI_MAX) priority = PRI_MAX;
  
  t->priority = priority;
}

/* 매 틱마다 현재 스레드의 recent_cpu 1 증가 */
void
mlfqs_increment_recent_cpu (void)
{
  struct thread *cur = thread_current ();
  if (cur == idle_thread) return;
  
  cur->recent_cpu = FP_ADD_INT (cur->recent_cpu, 1);
}

/* 1초 또는 4틱마다 모든 스레드의 값을 다시 계산 */
void
mlfqs_recalculate_all (void)
{
  struct list_elem *e;
  bool is_second = (timer_ticks () % TIMER_FREQ == 0);
  bool is_4th_tick = (timer_ticks () % TIME_SLICE == 0);

  if (is_second) mlfqs_update_load_avg ();

  for (e = list_begin (&all_list); e != list_end (&all_list); e = list_next (e))
  {
    struct thread *t = list_entry (e, struct thread, allelem);
    if (t == idle_thread) continue;

    if (is_second) mlfqs_calculate_recent_cpu (t);
    if (is_4th_tick) mlfqs_calculate_priority (t);
  }

  if (is_4th_tick)
  {
    for (int i = PRI_MIN; i <= PRI_MAX; i++)
    {
      struct list_elem *e = list_begin (&ready_list[i]);
      while (e != list_end (&ready_list[i]))
      {
        struct thread *t = list_entry (e, struct thread, elem);
        struct list_elem *next = list_next (e);
        if (t->priority != i)
        {
          /* 큐에서 제거하고 올바른 큐로 이동 */
          list_remove (e);
          list_push_back (&ready_list[t->priority], &t->elem);
        }
        e = next;
      }
    }
  }
}

/* Offset of `stack' member within `struct thread'.
   Used by switch.S, which can't figure it out on its own. */
uint32_t thread_stack_ofs = offsetof (struct thread, stack);
