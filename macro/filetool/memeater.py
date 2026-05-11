# test812: memeater
import time
import os

def getMem(size_gb):
    CHUNK_SIZE = 512 * 1048576 # 512MiB
    num_chunks = size_gb * 2
    memory_list = [ ]
    
    print(f"===== Starting Memory Filling {size_gb} GiB =====")
    try:
        for i in range(num_chunks):
            memory_list.append(bytearray(CHUNK_SIZE))
            print(f"{len(memory_list)/2} / {size_gb} GiB")
            time.sleep(0.1) # give time to OS page swap
            
    except MemoryError:
        print("\nOS refused to allocate memory")
    except KeyboardInterrupt:
        print("\nHalted by User Interupt")

    print("===== Memory Filling Completed =====\nAuto Exit in 30 seconds")
    time.sleep(30)

getMem(4)
