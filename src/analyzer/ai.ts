/**
 * AI Code Explanation Engine
 * Part of the Universal Reverse Engineering Tool (URET)
 * Simulates/stubs a local AI assistant that analyzes disassembled or decompiled code blocks.
 */

export interface AIPattern {
  name: string;
  confidence: number; // 0 to 100
  description: string;
  matchedElements: string[];
}

export interface AIComplexity {
  time: string;
  space: string;
}

export interface AIExplanationResult {
  summary: string;
  functionality: string[];
  patterns: AIPattern[];
  pseudocode: string;
  complexity: AIComplexity;
  suggestions: string[];
}

export class AIExplanationEngine {
  /**
   * Analyzes a block of code (assembly or decompiled) and returns an AI explanation result.
   */
  public static analyze(code: string, context?: { functionName?: string; arch?: string }): AIExplanationResult {
    const cleanCode = code.trim();
    const funcName = context?.functionName || 'unknown_function';
    const lowerCode = cleanCode.toLowerCase();

    // Default response state
    let summary = `Analyzes a sub-routine '${funcName}' and coordinates register/memory structures.`;
    const functionality: string[] = [];
    const patterns: AIPattern[] = [];
    let pseudocode = '';
    let timeComp = 'O(N)';
    let spaceComp = 'O(1)';
    const suggestions: string[] = [];

    // Analyze specific patterns
    const hasRC4 = lowerCode.includes('rc4') || (lowerCode.includes('256') && lowerCode.includes('swap') && lowerCode.includes('xor')) || (lowerCode.includes('s[i]') && lowerCode.includes('s[j]'));
    const hasTEA = lowerCode.includes('0x9e3779b9') || lowerCode.includes('0x61c88647') || lowerCode.includes('tea') || lowerCode.includes('xtea');
    const hasBase64 = lowerCode.includes('base64') || lowerCode.includes('abcdefghijklmnopqrstuvwxyz') || (lowerCode.includes('0x3f') && lowerCode.includes('>>') && lowerCode.includes('<<'));
    const hasXorObfuscation = (lowerCode.includes('xor') && (lowerCode.includes('key') || lowerCode.includes('crypt') || lowerCode.includes('obfus') || lowerCode.includes('0xaa') || lowerCode.includes('0x55')));
    const hasAntiDebug = lowerCode.includes('isdebuggerpresent') || lowerCode.includes('peb') || lowerCode.includes('ntglobalflag') || lowerCode.includes('fs:[0x30]') || lowerCode.includes('gs:[0x60]') || lowerCode.includes('ptrace');
    const hasNetwork = lowerCode.includes('socket') || lowerCode.includes('connect') || lowerCode.includes('send') || lowerCode.includes('recv') || lowerCode.includes('http') || lowerCode.includes('socket');
    const hasFileSystem = lowerCode.includes('fopen') || lowerCode.includes('fread') || lowerCode.includes('fwrite') || lowerCode.includes('fclose') || lowerCode.includes('createfile') || lowerCode.includes('readfile');
    const hasStringManip = lowerCode.includes('strcmp') || lowerCode.includes('strlen') || lowerCode.includes('strcpy') || lowerCode.includes('strcat') || lowerCode.includes('memcpy') || lowerCode.includes('memset');
    const hasMath = lowerCode.includes('imul') || lowerCode.includes('idiv') || lowerCode.includes('mul') || lowerCode.includes('div') || lowerCode.includes('sin') || lowerCode.includes('cos') || lowerCode.includes('sqrt');
    const hasLoops = lowerCode.includes('while') || lowerCode.includes('for') || lowerCode.includes('loop') || lowerCode.includes('jz') || lowerCode.includes('jnz') || lowerCode.includes('jmp');

    // 1. MATCH: RC4 Stream Cipher
    if (hasRC4 || funcName.toLowerCase().includes('rc4') || funcName.toLowerCase().includes('ksa') || funcName.toLowerCase().includes('prga')) {
      summary = `Implements the RC4 stream cipher algorithm, including either the Key Scheduling Algorithm (KSA) or the Pseudo-Random Generation Algorithm (PRGA).`;
      functionality.push(
        'Initializes an S-box array of 256 bytes with values from 0 to 255.',
        'Permutes the S-box based on the bytes of a provided secret key.',
        'Generates a pseudo-random keystream of bytes via continuous S-box swapping.',
        'Performs bitwise XOR between input plaintext bytes and the keystream to produce ciphertext.'
      );
      patterns.push({
        name: 'RC4 Cryptographic Cipher',
        confidence: 95,
        description: 'Symmetric stream cipher characterized by a state array of 256 bytes, swapping indexes, and XOR stream combining.',
        matchedElements: ['S-box initialization loop (0..255)', 'S-box permutation based on key bytes', 'Index arithmetic wrapping modulo 256']
      });
      pseudocode = `void rc4_crypt(uint8_t *data, size_t data_len, const uint8_t *key, size_t key_len) {
    uint8_t S[256];
    int i, j = 0;
    
    // Key Scheduling Algorithm (KSA)
    for (i = 0; i < 256; i++) {
        S[i] = i;
    }
    for (i = 0; i < 256; i++) {
        j = (j + S[i] + key[i % key_len]) & 0xFF;
        swap(&S[i], &S[j]);
    }
    
    // Pseudo-Random Generation Algorithm (PRGA) & XOR
    i = 0; j = 0;
    for (size_t offset = 0; offset < data_len; offset++) {
        i = (i + 1) & 0xFF;
        j = (j + S[i]) & 0xFF;
        swap(&S[i], &S[j]);
        uint8_t K = S[(S[i] + S[j]) & 0xFF];
        data[offset] ^= K; // Encrypt/Decrypt byte
    }
}`;
      timeComp = 'O(N) where N is the length of data (plus O(1) constant initialization overhead)';
      spaceComp = 'O(1) auxiliary space (256 bytes on the stack for S-box state)';
      suggestions.push(
        'RC4 is cryptographically broken and vulnerable to various attacks (e.g., Fluhrer-Mantin-Shamir). Upgrade to AES-GCM or ChaCha20.',
        'Ensure the secret key is not hardcoded in the binary assets.'
      );
    }
    // 2. MATCH: TEA / XTEA Block Cipher
    else if (hasTEA || funcName.toLowerCase().includes('tea') || funcName.toLowerCase().includes('xtea')) {
      summary = `Implements the Tiny Encryption Algorithm (TEA or XTEA), a symmetric block cipher renowned for its simple design and compact code size.`;
      functionality.push(
        'Operates on 64-bit blocks of data split into two 32-bit halves (v0, v1).',
        'Applies a 128-bit key partitioned into four 32-bit subkeys (k0, k1, k2, k3).',
        'Uses a golden ratio constant (delta = 0x9E3779B9) to offset the key schedule in each round.',
        'Executes 32 rounds of mixed addition, bitwise shift, and bitwise XOR operations.'
      );
      patterns.push({
        name: 'TEA/XTEA Block Cipher',
        confidence: 98,
        description: 'Feistel cipher utilizing a delta constant of 0x9E3779B9 and repetitive bitwise shifts.',
        matchedElements: ['Delta constant 0x9E3779B9', 'Bitwise shift operations (<< 4, >> 5)', 'Accumulative sum loop (usually 32 iterations)']
      });
      pseudocode = `void xtea_encrypt(uint32_t num_rounds, uint32_t v[2], const uint32_t k[4]) {
    uint32_t v0 = v[0], v1 = v[1], sum = 0, delta = 0x9E3779B9;
    for (uint32_t i = 0; i < num_rounds; i++) {
        v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + k[sum & 3]);
        sum += delta;
        v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + k[(sum >> 11) & 3]);
    }
    v[0] = v0; v[1] = v1;
}`;
      timeComp = 'O(R) where R is the number of rounds (typically 32 or 64, making it effectively O(1))';
      spaceComp = 'O(1) storage in registers';
      suggestions.push(
        'TEA has a key-equivalence vulnerability (each key is equivalent to three others). Ensure XTEA or block padding is used correctly.',
        'Verify that blocks are chained together via a secure mode of operation (like CBC or GCM) rather than ECB mode.'
      );
    }
    // 3. MATCH: Base64 Encoding / Decoding
    else if (hasBase64 || funcName.toLowerCase().includes('base64') || funcName.toLowerCase().includes('b64')) {
      summary = `Implements Base64 processing (encoding or decoding) to represent binary data in an ASCII string format.`;
      functionality.push(
        'Processes data in chunks of 3 bytes (encoding) or 4 characters (decoding).',
        'Maps 6-bit index values to printable characters using a standard character lookup table.',
        'Applies padding character "=" as necessary at the end of the payload.'
      );
      patterns.push({
        name: 'Base64 Text Conversion',
        confidence: 90,
        description: 'Binary-to-text encoding scheme utilizing a 64-character lookup table and bit-packing operations.',
        matchedElements: ['Lookup alphabet: A-Z, a-z, 0-9, +, /', 'Bitwise masking (e.g., & 0x3F)', 'Modulo 3/4 padding blocks']
      });
      pseudocode = `char* base64_encode(const uint8_t* data, size_t input_len) {
    const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t output_len = 4 * ((input_len + 2) / 3);
    char* encoded = (char*)malloc(output_len + 1);
    
    for (size_t i = 0, j = 0; i < input_len; ) {
        uint32_t octet_a = i < input_len ? data[i++] : 0;
        uint32_t octet_b = i < input_len ? data[i++] : 0;
        uint32_t octet_c = i < input_len ? data[i++] : 0;
        uint32_t triple = (octet_a << 16) | (octet_b << 8) | octet_c;
        
        encoded[j++] = alphabet[(triple >> 18) & 0x3F];
        encoded[j++] = alphabet[(triple >> 12) & 0x3F];
        encoded[j++] = i > input_len + 1 ? '=' : alphabet[(triple >> 6) & 0x3F];
        encoded[j++] = i > input_len ? '=' : alphabet[triple & 0x3F];
    }
    encoded[output_len] = '\\0';
    return encoded;
}`;
      timeComp = 'O(N) where N is the length of the input data stream';
      spaceComp = 'O(N) to hold the output string representation';
      suggestions.push(
        'Base64 is NOT encryption. It is a transmission encoding. Never use Base64 to conceal passwords or sensitive cryptographic material.'
      );
    }
    // 4. MATCH: Anti-Debugging or Malware Obfuscation
    else if (hasAntiDebug || funcName.toLowerCase().includes('debug') || funcName.toLowerCase().includes('anti')) {
      summary = `Implements security protections or anti-analysis checks, aiming to determine if the process is currently being inspected inside a debugger or emulator.`;
      functionality.push(
        'Queries the Process Environment Block (PEB) for the BeingDebugged flag.',
        'Checks NtGlobalFlag or reads processor Thread Information Block directly.',
        'May issue specialized API requests (e.g., IsDebuggerPresent, CheckRemoteDebuggerPresent, or ptrace).',
        'Conditional branching changes program behavior or terminates execution if debugging is detected.'
      );
      patterns.push({
        name: 'Anti-Debugging & Evasion',
        confidence: 95,
        description: 'Standard software protection / malware technique to inhibit reverse engineering.',
        matchedElements: ['PEB dereference (fs:[0x30] or gs:[0x60])', 'API check: IsDebuggerPresent', 'Branching logic indicating execution deviation']
      });
      pseudocode = `bool is_being_debugged() {
#ifdef _WIN32
    // Read BeingDebugged byte directly from PEB (x86 structure)
    uint8_t* peb;
    __asm {
        mov eax, fs:[30h]
        mov peb, eax
    }
    if (peb[2] != 0) return true; // BeingDebugged flag
    
    // Check NtGlobalFlag at offset 0x68
    uint32_t ntGlobalFlag = *(uint32_t*)(peb + 0x68);
    if (ntGlobalFlag & 0x70) return true;
#else
    // Unix ptrace check
    if (ptrace(PTRACE_TRACEME, 0, 1, 0) < 0) {
        return true; // Already traced (debugged)
    }
#endif
    return false;
}`;
      timeComp = 'O(1) constant-time direct memory lookup or system call';
      spaceComp = 'O(1) auxiliary space';
      suggestions.push(
        'For binary hardening, anti-debugging makes basic static analysis harder but is easily bypassed with hooks, plugins (ScyllaHide), or instruction patching.',
        'Consider using advanced control-flow flattening or code virtualization instead of basic PEB checks.'
      );
    }
    // 5. MATCH: XOR Cryptography / Obfuscation
    else if (hasXorObfuscation || funcName.toLowerCase().includes('xor') || funcName.toLowerCase().includes('crypt')) {
      summary = `Applies a XOR-based encryption or obfuscation routine to strings, binary contents, or communication buffers.`;
      functionality.push(
        'Iterates over an array or buffer of bytes.',
        'Applies a logical XOR operator against a fixed key byte, a key sequence, or a cyclic key buffer.',
        'Often used for payload decryption or concealing static strings to bypass antivirus signatures.'
      );
      patterns.push({
        name: 'XOR Obfuscation / Decryption',
        confidence: 85,
        description: 'Simplistic symmetric operation for data masking.',
        matchedElements: ['Loop containing XOR register or XOR byte instruction', 'Cyclic key indexing (modulo key length)', 'In-place buffer mutation']
      });
      pseudocode = `void xor_cipher(uint8_t* data, size_t data_len, const uint8_t* key, size_t key_len) {
    for (size_t i = 0; i < data_len; i++) {
        data[i] ^= key[i % key_len];
    }
}`;
      timeComp = 'O(N) where N is the length of data';
      spaceComp = 'O(1) in-place transformation';
      suggestions.push(
        'XOR obfuscation is easily broken using frequency analysis or plain-text attacks. Avoid using it for actual security applications.',
        'If used for string masking, keep the XOR keys random and rotate them frequently.'
      );
    }
    // 6. MATCH: Network Sockets
    else if (hasNetwork || funcName.toLowerCase().includes('net') || funcName.toLowerCase().includes('socket') || funcName.toLowerCase().includes('http')) {
      summary = `Manages network connectivity, opening a socket or making API calls to establish external communication.`;
      functionality.push(
        'Initializes socket libraries (e.g., WSAStartup on Windows).',
        'Resolves remote domains or sets up server sockaddr structures (IP address, port).',
        'Calls connect() to hook into a remote host or listen() to wait for incoming requests.',
        'Handles transmission or reception of byte streams (send, recv, read, write).'
      );
      patterns.push({
        name: 'Network TCP/IP Socket client',
        confidence: 90,
        description: 'Establishes a socket socket descriptor and attempts a socket connection to a remote IP address.',
        matchedElements: ['socket() invocation', 'sockaddr_in structure configuration', 'connect() or send()/recv() flow']
      });
      pseudocode = `int establish_connection(const char* ip, int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;
    
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &server_addr.sin_addr);
    
    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        close(sock);
        return -1;
    }
    return sock;
}`;
      timeComp = 'O(1) (network bounded wait time)';
      spaceComp = 'O(1) descriptors and config structs';
      suggestions.push(
        'Inspect the IP addresses or domain names referenced by this function to identify potential Command & Control (C2) domains.',
        'Ensure that any network traffic transmitting sensitive data uses TLS (HTTPS/WSS) instead of cleartext TCP sockets.'
      );
    }
    // 7. MATCH: File System I/O
    else if (hasFileSystem || funcName.toLowerCase().includes('file') || funcName.toLowerCase().includes('write') || funcName.toLowerCase().includes('read')) {
      summary = `Performs file system input/output operations, writing, reading, or creating files on disk.`;
      functionality.push(
        'Obtains a file descriptor or file handle using file paths.',
        'Applies appropriate modes (read, write, append, binary).',
        'Reads chunks of bytes into memory buffers or commits memory buffers down to disk.',
        'Closes the file descriptor to flush caches and release lock resources.'
      );
      patterns.push({
        name: 'File System Access',
        confidence: 85,
        description: 'Read or write interface interacting with storage files.',
        matchedElements: ['fopen / CreateFile call', 'fread / ReadFile or fwrite / WriteFile operations', 'fclose / CloseHandle cleanup']
      });
      pseudocode = `size_t write_buffer_to_file(const char* filepath, const uint8_t* buffer, size_t size) {
    FILE* f = fopen(filepath, "wb");
    if (!f) return 0;
    size_t written = fwrite(buffer, 1, size, f);
    fclose(f);
    return written;
}`;
      timeComp = 'O(N) where N is the size of the buffer to write/read';
      spaceComp = 'O(1) auxiliary space (excluding buffer itself)';
      suggestions.push(
        'Verify path sanitization is in place to prevent path traversal vulnerabilities (e.g., passing "../../etc/passwd.js").',
        'Check if file access checks are performed correctly before writing critical files.'
      );
    }
    // 8. MATCH: String Manipulation
    else if (hasStringManip || funcName.toLowerCase().includes('string') || funcName.toLowerCase().includes('str')) {
      summary = `Executes string manipulation or memory copying, typically checking string lengths, concatenating strings, or looking for specific substring tokens.`;
      functionality.push(
        'Loops through string pointers seeking null-terminator bytes.',
        'Compares byte buffers to evaluate equality or ordering (lexicographical check).',
        'Copies character blocks from a source buffer into a destination buffer.'
      );
      patterns.push({
        name: 'String / Buffer Processing',
        confidence: 80,
        description: 'Common string utility logic often compiled inline or via runtime libc imports.',
        matchedElements: ['Pointer arithmetic/iteration until null-byte', 'Comparison loops with offset increments', 'String functions like strcmp, strlen']
      });
      pseudocode = `size_t my_strlen(const char* str) {
    const char* s = str;
    while (*s) {
        s++;
    }
    return s - str;
}`;
      timeComp = 'O(N) where N is string length';
      spaceComp = 'O(1) index descriptors';
      suggestions.push(
        'Ensure destination buffers are allocated with sufficient capacity (including space for the null terminator) to prevent memory corruption / buffer overflow.',
        'Prefer bounded string operations (like strncat, strncpy, snprintf) over unbounded equivalents (strcat, strcpy, sprintf).'
      );
    }
    // 9. MATCH: General Math Calculation
    else if (hasMath || funcName.toLowerCase().includes('math') || funcName.toLowerCase().includes('calc')) {
      summary = `Executes mathematical or numeric computations, likely processing geometry, checksums, hash constants, or statistical calculations.`;
      functionality.push(
        'Runs multiplicative and division operations on double/float or large integer types.',
        'Performs scaling, bitwise shifts, or offset additions to transform numeric variables.'
      );
      patterns.push({
        name: 'Mathematical Routine',
        confidence: 75,
        description: 'General numeric processing function.',
        matchedElements: ['imul / idiv / fmul instructions', 'Floating point operations', 'Mathematical formulas / lookup coefficients']
      });
      pseudocode = `double calculate_hypotenuse(double side1, double side2) {
    return sqrt((side1 * side1) + (side2 * side2));
}`;
      timeComp = 'O(1) constant-time arithmetic execution';
      spaceComp = 'O(1) register allocation';
      suggestions.push(
        'Verify that division operations validate divisor boundaries to prevent division-by-zero crashes.',
        'Watch for integer overflow or underflow conditions during multiplier cycles.'
      );
    }
    // 10. DEFAULT / Iterative loop
    else {
      summary = `Implements an iterative control loop processing general buffer items or variables inside '${funcName}'.`;
      functionality.push(
        'Initializes loop counter variables and index flags.',
        'Applies logical comparison instructions (CMP/TEST) to manage conditional jumps.',
        'Reads variables, registers, or memory buffers sequentially.'
      );
      if (hasLoops) {
        patterns.push({
          name: 'Looping Iterative Routine',
          confidence: 80,
          description: 'Basic control loop evaluating a sequential block of instructions.',
          matchedElements: ['Loop counter initialization', 'Conditional branches (JZ/JNZ/JNE/JLE)', 'Pointer step increment']
        });
      }
      pseudocode = `void process_items(uint32_t* items, size_t count) {
    for (size_t i = 0; i < count; i++) {
        // Core block operations
        uint32_t temp = items[i];
        temp = (temp ^ 0x3D) + 0x10;
        items[i] = temp;
    }
}`;
      timeComp = 'O(N) where N is number of iterations';
      spaceComp = 'O(1)';
      suggestions.push(
        'Ensure loop index boundaries are securely bounded relative to target buffer allocations to block out-of-bounds reads/writes.'
      );
    }

    return {
      summary,
      functionality,
      patterns,
      pseudocode,
      complexity: {
        time: timeComp,
        space: spaceComp
      },
      suggestions
    };
  }
}
