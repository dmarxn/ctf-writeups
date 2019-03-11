# Description #
This challenge was in TUMctf by hxp, it's an old challenge with many write ups.

Back when that ctf was live I solved it by emulating with python and didn't know about unicorn-engine.
However, this is a classic example to show how unicorn-engine can be useful.
If you don't know about unicorn, it's a CPU emulator which lets your run shellcode and hook it.
You can check it out in the [official site](https://www.unicorn-engine.org) or [the repo](https://github.com/unicorn-engine/unicorn)

The program basically runs a shellcode, in which the input (flag) is checked bit by bit, but not in order.
You can see the first check only, because after it the code is xor encrypted with some key. If the first check succeed, the program xors the next part and so on...

![Image of first block](https://github.com/dmarxn/ctf-writeups/blob/master/tumctf-2016/zwiebel/one_block.png)

This continues until all the layers of the onion (zwiebel) are peeled.

# Solution #

So to automate the check : 

1. The offset from rax, is the position of the character in the flag
2. The number al is masked with represents the bit location in that byte.
3. The jump (jz/jnz) implies if the bit should be a 1 or a 0.

Hooking every instruction, the following hook can retrieve the flag :

```C
#define MOV_AL '\x8a'
#define TO_RAX '\x40'
#define AND_AL '\x24'
#define JZ '\x74'

#define SIZE_OF_BLOCK 7

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
```


Which gives us the flag: hxp{1_h0p3_y0u_d1dnt_p33l_th3_0ni0n_by_h4nd}

(The full solution source is added, and also a binary compiled with unicorn.)
