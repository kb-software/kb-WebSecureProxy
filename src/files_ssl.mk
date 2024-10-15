ifeq ($(findstring Win,$(PLATFORM)),Win)
    ASM_TYPE   := asm
    ASM_SUFFIX := win
else
    ASM_TYPE   := s
    ASM_SUFFIX := nasm
endif
ifeq ($(findstring X86,$(PLATFORM)),X86)
    FILES += $(SOLUTIONDIR)/$(WSP_SRC)/cpuaes86.$(ASM_TYPE) \
             $(SOLUTIONDIR)/$(WSP_SRC)/islock03-32-$(ASM_SUFFIX).$(ASM_TYPE) \
             $(SOLUTIONDIR)/$(WSP_SRC)/is-random-cas-02-32-$(ASM_SUFFIX).$(ASM_TYPE)
endif
ifeq ($(findstring X64,$(PLATFORM)),X64)
    FILES += $(SOLUTIONDIR)/$(WSP_SRC)/is-encry-2-x64.$(ASM_TYPE) \
             $(SOLUTIONDIR)/$(WSP_SRC)/cpuaes64.$(ASM_TYPE) \
             $(SOLUTIONDIR)/$(WSP_SRC)/islock03-64-$(ASM_SUFFIX).$(ASM_TYPE) \
             $(SOLUTIONDIR)/$(WSP_SRC)/is-random-cas-02-64-$(ASM_SUFFIX).$(ASM_TYPE)
endif
