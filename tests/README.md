# Firegex tests

## [GO BACK](../README.md)

Tests are a quick and dirty way to check if your modification to the backend code dind't break anything.

# Running a Test
    $ ./test.py 
    usage: test.py [-h] [--address ADDRESS] [--service_port SERVICE_PORT] [--service_name SERVICE_NAME] --password PASSWORD

If you are running firegex locally, just run ```test.py -p FIREGEX_PASSWORD```. Otherwise, select a remote address with  ```-a http://ADDRESS:PORT/``` .

Output of the tests:

    Testing will start on http://127.0.0.1:5000/
    Sucessfully logged in ✔
    Sucessfully created service Test Service with public port 1337 ✔
    Sucessfully received the internal port 38222 ✔
    Sucessfully started service with id test-service ✔
    Successfully tested first proxy with no regex ✔
    Sucessfully added regex to service with id test-service ✔
    The malicious request was successfully blocked ✔
    Sucessfully stopped service with id test-service ✔
    The request wasn't blocked ✔
    Sucessfully delete service with id test-service ✔

The testing methodology will soon be updated with more edge-cases.

# Running a Benchmark
    ./benchmark.py
    --address ADDRESS, -a ADDRESS
                            Address of firegex backend
    --service_port SERVICE_PORT, -P SERVICE_PORT
                            Port of the Benchmark service
    --service_name SERVICE_NAME, -n SERVICE_NAME
                            Name of the Benchmark service
    --password PASSWORD, -p PASSWORD
                            Firegex password
    --num_of_regexes NUM_OF_REGEXES, -r NUM_OF_REGEXES
                            Number of regexes to benchmark with
    --duration DURATION, -d DURATION
                            Duration of the Benchmark in seconds

Benchmarks let you evaluate the performance of the proxy. You can run one by typing in a shell  ```test.py -p FIREGEX_PASSWORD -r NUM_OF_REGEX -d BENCHMARK_DURATION```. 

It uses iperf3 to benchmark the throuput in MB/s of the server, both with proxy, without proxy, and for each new added regex. It will automatically add a new random regex untill it has reached NUM_OF_REGEX specified in the arguments. 

Example output:

    Benchmarking with 30 will start on http://127.0.0.1:5000/
    Sucessfully logged in ✔
    Sucessfully created service Benchmark Service with public port 1337 ✔
    Sucessfully received the internal port 38249 ✔
    Baseline without proxy: 7145.402353788159MB/s
    Sucessfully started service with id benchmark-service ✔
    Performance with no regexes: 2255.4573361742887MB/s
    Performance with 1 regex(s): 76.51810976542541MB/s
    Performance with 2 regex(s): 38.769568516424684MB/s
    Performance with 3 regex(s): 25.976997107893663MB/s
    Performance with 4 regex(s): 19.539058399917625MB/s
    Performance with 5 regex(s): 14.720692718915746MB/s
    Performance with 6 regex(s): 13.101487751340413MB/s
    Performance with 7 regex(s): 11.237772047509017MB/s
    Performance with 8 regex(s): 9.851833265188406MB/s
    Performance with 9 regex(s): 8.725255532797124MB/s
    Performance with 10 regex(s): 7.891516589287963MB/s