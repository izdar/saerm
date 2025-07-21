INCLUDES = -Iltl-parser

all: frame_structs.h
	gcc -w $(INCLUDES) -c h2e.c 
	gcc -w $(INCLUDES) -c driver.c
	gcc -w $(INCLUDES) -c looping.c 
	gcc -w $(INCLUDES) -c sendFrame.c
	gcc -w $(INCLUDES) -c utility.c
	gcc -w $(INCLUDES) -c oracle-parser.c
	gcc -w $(INCLUDES) -c replacement.c 
	gcc -w $(INCLUDES) -c sae_assoc.c
	#gcc  -w -o driver driver.c h2e.o looping.o sendFrame.o sae_assoc.o -lcrypto -lm 
	gcc  -w $(INCLUDES) -o ../fuzzer fuzzer.c utility.o driver.o oracle-parser.o replacement.o h2e.o looping.o sendFrame.o sae_assoc.o -lcrypto -lm 

tracereplayer:
	gcc -w $(INCLUDES) -c h2e.c 
	gcc -w $(INCLUDES) -c sendFrame.c
	gcc -w $(INCLUDES) -c driver.c
	gcc -w $(INCLUDES) -c looping.c 
	gcc -w $(INCLUDES) -c oracle-parser.c
	gcc -w $(INCLUDES) -c replacement.c 
	gcc -w $(INCLUDES) -c sae_assoc.c
	g++ -w $(INCLUDES) -c warningmsgs.cpp 
	g++ -w $(INCLUDES) -c wrapper.cpp 
	g++ -w $(INCLUDES) -c generalutil.cpp
	g++ -w $(INCLUDES) -c connection.cpp 
	g++ -w $(INCLUDES) -c tracereplayer.cpp
	g++ -w $(INCLUDES) -c ltl-parser/state.cpp
	g++ -w $(INCLUDES) -c ltl-parser/typechecker.cpp
	g++ -w $(INCLUDES) -c ltl-parser/bitvector.cpp
	g++ -w $(INCLUDES) -c ltl-parser/evaluator.cpp
	g++ -w $(INCLUDES) -c ltl-parser/memory_manager.cpp
	g++ -w $(INCLUDES) -c ltl-parser/preprocess.cpp
	flex -o lexer.cpp ltl-parser/lexer.l
	bison -d -o parser.cpp ltl-parser/parser.y
	g++ -w $(INCLUDES) -c ltl-parser/parser.cpp
	g++ -w $(INCLUDES) -c lexer.cpp -o lexer.o
	g++ -w $(INCLUDES) -o ../treplayer -DREPLAYER -DHOSTAPD main.cpp parser.o lexer.o memory_manager.o typechecker.o preprocess.o state.o evaluator.o bitvector.o tracereplayer.o warningmsgs.o wrapper.o generalutil.o connection.o driver.o oracle-parser.o replacement.o h2e.o looping.o sendFrame.o sae_assoc.o -lcrypto -lm

fuzzer:
	gcc -w $(INCLUDES) -c h2e.c 
	gcc -w $(INCLUDES) -c sendFrame.c
	gcc -w $(INCLUDES) -c driver.c
	gcc -w $(INCLUDES) -c looping.c 
	gcc -w $(INCLUDES) -c oracle-parser.c
	gcc -w $(INCLUDES) -c replacement.c 
	gcc -w $(INCLUDES) -c sae_assoc.c
	g++ -w $(INCLUDES) -c warningmsgs.cpp 
	g++ -w $(INCLUDES) -c wrapper.cpp 
	g++ -w $(INCLUDES) -c generalutil.cpp
	g++ -w $(INCLUDES) -c -DHOSTAPD connection.cpp 
	# g++ -w $(INCLUDES) -c -DAP connection.cpp 
	g++ -w $(INCLUDES) -c predicate_transformer.cpp
	g++ -w $(INCLUDES) -c ltl-parser/state.cpp
	g++ -w $(INCLUDES) -c ltl-parser/typechecker.cpp
	g++ -w $(INCLUDES) -c ltl-parser/bitvector.cpp
	g++ -w $(INCLUDES) -c ltl-parser/evaluator.cpp
	g++ -w $(INCLUDES) -c ltl-parser/memory_manager.cpp
	g++ -w $(INCLUDES) -c ltl-parser/preprocess.cpp
	flex -o lexer.cpp ltl-parser/lexer.l
	bison -d -o parser.cpp ltl-parser/parser.y
	g++ -w $(INCLUDES) -c parser.cpp
	g++ -w $(INCLUDES) -c lexer.cpp
	g++ -w $(INCLUDES) -c ltl-parser/ast_printer.cpp
	g++ -w $(INCLUDES) -c -DHOSTAPD fuzzer.cpp
	g++ -w $(INCLUDES) -o fuzzer -DFUZZER main.cpp ast_printer.o fuzzer.o parser.o lexer.o memory_manager.o typechecker.o preprocess.o state.o evaluator.o bitvector.o predicate_transformer.o warningmsgs.o wrapper.o generalutil.o connection.o driver.o oracle-parser.o replacement.o h2e.o looping.o sendFrame.o sae_assoc.o -lcrypto -lm


clean:
	rm -f *.o driver fuzzer treplayer 
	# rm -f *.o treplayer
