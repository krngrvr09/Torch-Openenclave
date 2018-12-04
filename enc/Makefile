# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# Detect C and C++ compiler options
# if not gcc and g++, default to clang-7
C_COMPILER=$(notdir $(CC))
ifeq ($(C_COMPILER), gcc)
		CXX_COMPILER=$(notdir $(CXX))
		USE_GCC = true
endif

ifeq ($(USE_GCC),)
		CC = clang-7
		CXX = clang++-7
		C_COMPILER=clang
		CXX_COMPILER=clang++
endif

CFLAGS=$(shell pkg-config oeenclave-$(C_COMPILER) --cflags)
CXXFLAGS=$(shell pkg-config oeenclave-$(CXX_COMPILER) --cflags)
LDFLAGS=$(shell pkg-config oeenclave-$(CXX_COMPILER) --libs)

THNN_Dir := $(CURDIR)/THNN
TH_Dir := $(CURDIR)/TH
Mbedtls_Dir := /home/karan/openenclave-install/include/openenclave

Enclave_Cpp_Files := encryptor.cpp ecalls.cpp keys.cpp 
Enclave_Include_Paths := -I$(TH_Dir) -I. -I$(THNN_Dir) -I$(Mbedtls_Dir)

Torch_C_Files := $(wildcard $(THNN_Dir)/*.c) $(wildcard $(TH_Dir)/*.c)
Enclave_Cpp_Objects := $(Enclave_Cpp_Files:.c=.o)
#Torch_C_Objects := $(Torch_C_Files:.cpp=.o)
Torch_C_Objects := /home/karan/samples/torchtestv3/enc/THNN/init.o /home/karan/samples/torchtestv3/enc/TH/THTensor.o /home/karan/samples/torchtestv3/enc/TH/THLogAdd.o /home/karan/samples/torchtestv3/enc/TH/THAllocator.o /home/karan/samples/torchtestv3/enc/TH/THGeneral.o /home/karan/samples/torchtestv3/enc/TH/THHalf.o /home/karan/samples/torchtestv3/enc/TH/THFile.o /home/karan/samples/torchtestv3/enc/TH/THBlas.o /home/karan/samples/torchtestv3/enc/TH/THAtomic.o /home/karan/samples/torchtestv3/enc/TH/THSize.o /home/karan/samples/torchtestv3/enc/TH/THLapack.o /home/karan/samples/torchtestv3/enc/TH/THVector.o /home/karan/samples/torchtestv3/enc/TH/THRandom.o /home/karan/samples/torchtestv3/enc/TH/THStorage.o
Enclave_Name := file-encryptorenc.so

CFLAGS += $(Enclave_Include_Paths)
CXXFLAGS += $(Enclave_Include_Paths)
CFLAGS += -g
CXXFLAGS += -g

all:
	$(MAKE) build
	$(MAKE) keys
	$(MAKE) sign

build: $(Torch_C_Objects)
	@ echo "Compilers used: $(CC), $(CXX)"
	@echo "$(CFLAGS)"
	@echo "hahahahaha"
	@echo "$(LDFLAGS)"
	@echo "1111111"
	@echo "$(Torch_C_Objects)"
	oeedger8r ../fileencryptor.edl --trusted
	$(CXX) -c $(CXXFLAGS) -std=c++11 ecalls.cpp encryptor.cpp keys.cpp
	$(CC) -c $(CFLAGS) fileencryptor_t.c -o fileencryptor_t.o
	#gcc -c $(Enclave_Include_Paths) $(wildcard $(THNN_Dir)/*.c) $(wildcard $(TH_Dir)/*.c)
	#$(CXX) -o file-encryptorenc.so ecalls.o encryptor.o keys.o fileencryptor_t.o $(LDFLAGS)
	#$(CC) $(CFLAGS) -o file-encryptorenc.so fileencryptor_t.o $(Torch_C_Objects) $(LDFLAGS)
	#gcc $(Enclave_Include_Paths) -fPIC -o file-encryptorenc.so $(Torch_C_Objects) $(LDFLAGS)
	ar rcs a.a ecalls.o encryptor.o keys.o fileencryptor_t.o
	ar rcs b.a fileencryptor_t.o $(Torch_C_Objects)
	gcc -shared -o file-encryptorenc.so $(LDFLAGS) a.a b.a $(LDFLAGS)

# all:
# 	$(MAKE) build
# 	# $(MAKE) keys
# 	# $(MAKE) sign

# build: $(Enclave_Name)
# 	@ echo "Compilers used: $(CC), $(CXX)"
# 	@ echo "Enclave_Include_Paths"

# fileencryptor_t.c: ../fileencryptor.edl
# 	@echo "11111"
# 	oeedger8r ../fileencryptor.edl --trusted
# 	@echo "GEN  =>  $@"

# fileencryptor_t.o: fileencryptor_t.c
# 	@echo "222"
# 	@$(CC) $(CFLAGS) -c $< -o $@
# 	@echo "CC   <=  $<"

%.o: %.cpp
	@echo "333"
	@$(CXX) -D ENCRYPTION_ENABLED=$(ENCRYPTION_ENABLED) $(CXXFLAGS)-c -std=c++11 $< -o $@
	@echo "CC   <=  $<"

$(TH_Dir)/%.o: $(TH_Dir)/%.c
	@echo "444"
	@$(CC) $(CFLAGS) -c $< -o $@
	@echo "CC  <=  $<"

$(THNN_Dir)/%.o: $(THNN_Dir)/%.c
	@echo "555"
	@$(CC) $(CFLAGS) -c $< -o $@
	@echo "CC  <=  $<"

# $(Enclave_Name): fileencryptor_t.o $(Enclave_Cpp_Objects) $(Torch_C_Objects)
# 	@echo "666"
# 	@$(CC) $(Enclave_Include_Paths) $^ -o $@ $(LDFLAGS) #Try adding -c $(CFLAGS)
# 	@echo "LINK =>  $@"

sign:
	oesign file-encryptorenc.so file-encryptor.conf private.pem

clean:
	rm -f *.so *.o fileencryptor_t.* fileencryptor_args.h private.pem public.pem

keys:
	openssl genrsa -out private.pem -3 3072
	openssl rsa -in private.pem -pubout -out public.pem


