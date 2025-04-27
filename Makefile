srcFolder = ./src/
objFolder = ./build/
srcFiles = $(wildcard $(srcFolder)*.cpp)
objects = $(patsubst $(srcFolder)%.cpp, $(objFolder)%.o, $(srcFiles))
cflags = -Wall -g -lssl -lcrypto -O3 `pkg-config fuse --cflags --libs`

all: clean CDCFS

debug: cflags += -DDEBUG -g
debug: all

CAFTL: cflags += -DCAFTL
CAFTL: all

NoDedupe: cflags += -DNODEDUPE
NoDedupe: all

$(objFolder)%.o: $(srcFolder)%.cpp
	@mkdir -p $(objFolder)
	$(CXX) $(cflags) -c -o $@ $<

CDCFS: $(objects)
	$(CXX) $(cflags) -o $@ $^

clean:
	rm -f CDCFS $(objFolder)*.o