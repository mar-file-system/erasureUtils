# Isa-l Multithreaded Benchmark

ec_parallel_benchmark options:

-D 		Enable RDMA server
-s 		RDMA server name (Required if -D specified)
-P <val>	RDMA server port number (Required if -D specified)
-N <val>	Number of NUMA nodes (Must be specified if NUMA awareness is desired)
-n <val>	Number of CPUs per NUMA node (Must be specified if -N present)
-c <val>	Compression option: 0 - No compression; 1 - Compression before encode; 2 - Compression after encode
-C <val>	CRC option: 0 - no CRC; 1 - CRC first; 2 - CRC between compression/encode; 3 - CRC after both compression/encode
-R <val>	Compression Ratio: 0 - random data; 0.25 - 4:1 compression ratio; 0.5 - 2:1 compression ratio; 0.75 - 1.3:1 compression ratio
-T <val>	CRC library: ZLIB - uses zlib adler32; IEEE - Intel Isa-l crc32_ieee; RFC: Intel Isa-l crc32_gzip_refl
-k <val>	Number of data blocks
-p <val>	Number of parity blocks
-b <val>	Block size (Maximum 1M), eg 32K, 64K, 1M
-t <val>	Number of threads
-d <val>	Per-thread input data size, eg 1G, 1000G

ec_rdma_client is RDMA benchmark client. It has the following options:

-k		Number of data blocks (MUST MATCH SERVER SIDE)
-n		Number of client (MUST match server -t value)
-i		Per-thread input data size, eg 1G, 500G
-b		Block size (MUST match server -b value)
-R		Compression Ratio, can be any value between 0 - 1
-s		RDMA server hostname (MUST match RDMA server -s value)
-p		Server port number (MUST match server side -P value)
-T <val>	CRC library: ZLIB - uses zlib adler32; IEEE - Intel Isa-l crc32_ieee; RFC: Intel Isa-l crc32_gzip_refl (MUST match server side -T value)
-C <val>	CRC option: 0 - no CRC; 1 - CRC first; 2 - CRC between compression/encode; 3 - CRC after both compression/encode (MUST match server side -C value)
-c <val>        Compression option: 0 - No compression; 1 - Compression before encode; 2 - Compression after encode (MUST match server side -c value)

NOTE: To benchmark RDMA, user must first start the server, then start client
