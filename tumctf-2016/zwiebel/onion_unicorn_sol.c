#include <unicorn/unicorn.h>
#include <string.h>


#define ADDRESS 0x0
#define FLAG_ADDRESS 0x400000
#define MOV_AL '\x8a'
#define TO_RAX '\x40'
#define AND_AL '\x24'
#define JZ '\x74'

#define SIZE_OF_BLOCK 7
#define FLAG_SIZE_MAX 100
#define SHC_LOCATION 0x1310
#define SIZE 0x24c80
#define PAGESIZE 0x1000
#define PAGEROUNDUP(x) ((x) + PAGESIZE - (x % PAGESIZE))

char flag[FLAG_SIZE_MAX] = { 0 };

// callback for tracing instruction
static void hook_code(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	uint64_t rip = 0;
	char instructions[SIZE_OF_BLOCK] = { 0 };
	char byte_at = 0;
	char bitmask = 0;

	if (uc_reg_read(uc, UC_X86_REG_RIP, &rip)) {
		printf("Error! couldn't read rip\n");
		return;
	}
	uc_mem_read(uc, rip, instructions, SIZE_OF_BLOCK);

	if (instructions[0] != MOV_AL || instructions[1] != TO_RAX || instructions[3] != AND_AL || instructions[5] != JZ) {
		return;
	}

	byte_at = instructions[2];
	bitmask = instructions[4];

	flag[byte_at] |= bitmask;
	uc_mem_write(uc, FLAG_ADDRESS, flag, FLAG_SIZE_MAX);
}



static void run_onion(char * buffer)
{
	uc_engine *uc;
	uc_err err;
	uc_hook trace;
	uint64_t rbx = FLAG_ADDRESS;
	// Initialize emulator in X86-32bit mode
	err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc);
	if (err) {
		printf("Failed on uc_open() with error returned: %u\n", err);
		return;
	}

	if (err = uc_mem_map(uc, ADDRESS, PAGEROUNDUP(SIZE), UC_PROT_ALL)) {
		printf("Error mapping emulation memory with error returned: %u\n", err);
	}
	if (err = uc_mem_map(uc, FLAG_ADDRESS, PAGEROUNDUP(sizeof(flag)), UC_PROT_ALL)) {
		printf("Error mapping flag memory with error returned: %u\n", err);
	}

	// write machine code to be emulated to memory
	if (uc_mem_write(uc, ADDRESS, buffer, SIZE)) {
		printf("Failed to write emulation code to memory, quit!\n");
		return;
	}

	if (uc_mem_write(uc, FLAG_ADDRESS, flag, sizeof(flag))) {
		printf("Failed to write flag to memory, quit!\n");
		return;
	}
	// initialize machine registers
	uc_reg_write(uc, UC_X86_REG_RBX, &rbx);
	// tracing all instruction by having @begin > @end
	uc_hook_add(uc, &trace, UC_HOOK_CODE, hook_code, NULL, 1, 0);


	// emulate machine code in infinite time
	err = uc_emu_start(uc, ADDRESS, ADDRESS + SIZE, 0, 0);
	printf("%s\n", flag);

	uc_close(uc);
}



int main(int argc, char **argv, char **envp)
{
	FILE * target;
	char * buffer;
	if (argc == 2) {

		target = fopen(argv[1], "rb");
		if (target <= 0) {
			return 1;
		}

		fseek(target, SHC_LOCATION, SEEK_SET);
		buffer = malloc(SIZE);
		if (buffer) {
			if (fread(buffer, 1, SIZE, target)) {
				run_onion(buffer);
			}
			free(buffer);
		}
		fclose(target);
	}
	else {
		printf("Usage %s <path_to_onion>\n", argv[0]);

	}

	return 0;
}
