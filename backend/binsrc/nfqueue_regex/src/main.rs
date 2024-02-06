use atomic_refcell::AtomicRefCell;
use nfq::{Queue, Verdict};
use std::cell::{Cell, RefCell};
use std::env;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::atomic::{AtomicPtr, AtomicU32};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Arc;
use std::thread::{self, sleep, sleep_ms, JoinHandle};

enum WorkerMessage {
    Error(String),
    Dropped(usize),
}

impl ToString for WorkerMessage {
    fn to_string(&self) -> String {
        match self {
            WorkerMessage::Error(e) => format!("E{}", e),
            WorkerMessage::Dropped(d) => format!("D{}", d),
        }
    }
}
struct Pool {
    _workers: Vec<Worker>,
    pub start: u16,
    pub end: u16,
}

const QUEUE_BASE_NUM: u16 = 1000;
impl Pool {
    fn new(threads: u16, tx: Sender<WorkerMessage>, db: RefCell<&str>) -> Self {
        // Find free queues
        let mut start = QUEUE_BASE_NUM;
        let mut queues: Vec<(Queue, u16)> = vec![];
        while queues.len() != threads.into() {
            for queue_num in
                (start..start.checked_add(threads + 1).expect("No more queues left")).rev()
            {
                let mut queue = Queue::open().unwrap();
                if queue.bind(queue_num).is_err() {
                    start = queue_num;
                    while let Some((mut q, num)) = queues.pop() {
                        let _ = q.unbind(num);
                    }
                    break;
                };
                queues.push((queue, queue_num));
            }
        }

        Pool {
            _workers: queues
                .into_iter()
                .map(|(queue, queue_num)| Worker::new(queue, queue_num, tx.clone()))
                .collect(),
            start,
            end: (start + threads),
        }
    }

    // fn join(self) {
    //     for worker in self._workers {
    //         let _ = worker.join();
    //     }
    // }
}

struct Worker {
    _inner: JoinHandle<()>,
}

impl Worker {
    fn new(mut queue: Queue, _queue_num: u16, tx: Sender<WorkerMessage>) -> Self {
        Worker {
            _inner: thread::spawn(move || loop {
                let mut msg = queue.recv().unwrap_or_else(|_| {
                    let _ = tx.send(WorkerMessage::Error("Fuck".to_string()));
                    panic!("");
                });

                msg.set_verdict(Verdict::Accept);
                queue.verdict(msg).unwrap();
            }),
        }
    }
}
struct InputOuputPools {
    pub output_queue: Pool,
    pub input_queue: Pool,
    rx: Receiver<WorkerMessage>,
}
impl InputOuputPools {
    fn new(threads: u16) -> InputOuputPools {
        let (tx, rx) = mpsc::channel();
        InputOuputPools {
            output_queue: Pool::new(threads / 2, tx.clone(), RefCell::new("ciao")),
            input_queue: Pool::new(threads / 2, tx, RefCell::new("miao")),
            rx,
        }
    }

    fn poll_events(&self) {
        loop {
            let event = self.rx.recv().expect("Channel has hung up");
            println!("{}", event.to_string());
        }
    }
}

static mut DB: AtomicPtr<Arc<u32>> = AtomicPtr::new(std::ptr::null_mut() as *mut Arc<u32>);

fn main() -> std::io::Result<()> {
    let mut my_x: Arc<u32> = Arc::new(0);
    let my_x_ptr: *mut Arc<u32> = std::ptr::addr_of_mut!(my_x);

    unsafe { DB.store(my_x_ptr, std::sync::atomic::Ordering::SeqCst) };

    thread::spawn(|| loop {
        let x_ptr = unsafe { DB.load(std::sync::atomic::Ordering::SeqCst) };
        let x = unsafe { (*x_ptr).clone() };
        dbg!(x);
        //sleep_ms(1000);
    });

    for i in 0..1000000000 {
        let mut my_x: Arc<u32> = Arc::new(i);
        let my_x_ptr: *mut Arc<u32> = std::ptr::addr_of_mut!(my_x);
        unsafe { DB.store(my_x_ptr, std::sync::atomic::Ordering::SeqCst) };
        //sleep_ms(100);
    }

    let mut threads = env::var("NPROCS").unwrap_or_default().parse().unwrap_or(2);
    if threads % 2 != 0 {
        threads += 1;
    }

    let in_out_pools = InputOuputPools::new(threads);
    eprintln!(
        "[info] [main] Input queues: {}:{}",
        in_out_pools.input_queue.start, in_out_pools.input_queue.end
    );
    eprintln!(
        "[info] [main] Output queues: {}:{}",
        in_out_pools.output_queue.start, in_out_pools.output_queue.end
    );
    in_out_pools.poll_events();
    Ok(())
}
