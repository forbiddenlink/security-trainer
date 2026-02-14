import type { Module } from "../../types";

export const fileUpload: Module = {
  id: "file-upload",
  title: "File Upload Vulnerabilities",
  description:
    "Master the security risks of file uploads and how to implement safe upload handling.",
  difficulty: "Intermediate",
  xpReward: 350,
  locked: false,
  lessons: [
    {
      id: "upload-theory",
      title: "Understanding File Upload Risks",
      type: "theory",
      content: `
# File Upload Vulnerabilities

File upload functionality is one of the most dangerous features to implement. When done incorrectly, it can lead to complete server compromise.

## Mission Briefing: The Attack Vectors

### 1. Remote Code Execution (RCE)
Uploading executable files (PHP, JSP, ASPX) that the server then executes:

\`\`\`
upload.php?file=shell.php
→ Server saves to /uploads/shell.php
→ Attacker visits /uploads/shell.php
→ Server executes attacker's code
\`\`\`

### 2. Path Traversal via Filename
Malicious filenames can escape the upload directory:
\`\`\`
filename: "../../../etc/cron.d/backdoor"
\`\`\`

### 3. Content-Type Bypass
Attackers send malicious files with innocent Content-Type headers:
\`\`\`
Content-Type: image/jpeg
[Actually contains PHP code]
\`\`\`

### 4. Double Extensions
Files like \`shell.php.jpg\` may be processed as PHP on misconfigured servers.

### 5. Polyglot Files
Files that are valid as multiple formats (e.g., a file that's both a valid JPEG and valid PHP).

## Real-World Intel

**Case File: Equifax (2017)**
Attackers exploited a file upload vulnerability in Apache Struts to upload a webshell, leading to the breach of 147 million records.

**Case File: Facebook (2016)**
A researcher discovered that uploaded images weren't properly validated, allowing SSRF via specially crafted image URLs.

## Defense Strategies

1. **Validate file type by content** - Check magic bytes, not just extension
2. **Rename uploaded files** - Use random UUIDs, not user-provided names
3. **Store outside webroot** - Serve via a download script, not direct access
4. **Set Content-Disposition** - Force download, prevent browser execution
5. **Limit file size** - Prevent DoS via large uploads
6. **Scan for malware** - Use antivirus on uploaded content
7. **Use separate domain** - Serve user content from isolated domain
            `,
    },
    {
      id: "upload-quiz-1",
      title: "Attack Vector Recognition",
      type: "quiz",
      content: "",
      quiz: {
        question:
          "An attacker uploads 'profile.php' as their avatar. The server saves it to /uploads/ and serves files directly. What can happen?",
        options: [
          "Nothing - browsers won't execute PHP files",
          "The PHP code executes when anyone views the 'avatar'",
          "The file is automatically converted to an image",
          "The server rejects all non-image uploads",
        ],
        correctAnswer: 1,
        explanation:
          "If the web server (Apache/Nginx) is configured to execute PHP files and the uploads directory allows execution, visiting /uploads/profile.php will run the attacker's code. This is Remote Code Execution (RCE).",
      },
    },
    {
      id: "upload-quiz-2",
      title: "Validation Bypass Knowledge",
      type: "quiz",
      content: "",
      quiz: {
        question:
          "A developer validates uploads by checking if the filename ends with '.jpg'. How can an attacker bypass this?",
        options: [
          "It cannot be bypassed - extension checking is secure",
          "Upload shell.php.jpg - some servers execute based on first extension",
          "Change the file's creation date",
          "Compress the file first",
        ],
        correctAnswer: 1,
        explanation:
          "Double extensions like 'shell.php.jpg' can bypass simple extension checks. Some server configurations (especially Apache with certain handlers) may execute the file as PHP based on the .php in the name. Always validate by content/magic bytes, not extension.",
      },
    },
    {
      id: "upload-quiz-3",
      title: "Secure Storage Pattern",
      type: "quiz",
      content: "",
      quiz: {
        question: "What is the SAFEST way to store uploaded files?",
        options: [
          "In the web root with execution disabled",
          "Outside the web root, served via a download controller with Content-Disposition",
          "In the database as BLOBs",
          "On a CDN with public access",
        ],
        correctAnswer: 1,
        explanation:
          "Storing outside the web root prevents direct access. Serving via a controller allows access control and setting Content-Disposition: attachment forces download instead of browser execution. Database storage works but is inefficient; CDNs need careful configuration.",
      },
    },
    {
      id: "upload-quiz-4",
      title: "Content-Type Validation",
      type: "quiz",
      content: "",
      quiz: {
        question:
          "Why shouldn't you trust the Content-Type header sent by the client?",
        options: [
          "Browsers sometimes send wrong Content-Types",
          "Attackers can set any Content-Type they want - it's just a header",
          "Content-Type only affects download speed",
          "Old browsers don't support Content-Type",
        ],
        correctAnswer: 1,
        explanation:
          "The Content-Type header is sent by the client and can be set to anything. An attacker can upload 'malware.exe' with Content-Type: image/jpeg. Always validate file content by checking magic bytes (file signatures) at the start of the file.",
      },
    },
    {
      id: "upload-lab",
      title: "Secure the Upload Handler",
      type: "lab",
      content:
        "The code below accepts file uploads without proper validation. Your mission: Add security checks to prevent malicious uploads.",
      lab: {
        initialCode: `
const path = require('path');
const fs = require('fs');

const UPLOAD_DIR = '/var/www/uploads';

function handleUpload(req, res) {
  const file = req.files.upload;
  const filename = file.name;

  // VULNERABLE: No validation!
  const savePath = path.join(UPLOAD_DIR, filename);

  fs.writeFileSync(savePath, file.data);

  res.json({ url: '/uploads/' + filename });
}
                `,
        solutionCode: `
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const UPLOAD_DIR = '/var/www/uploads';
const ALLOWED_TYPES = ['image/jpeg', 'image/png', 'image/gif'];
const MAX_SIZE = 5 * 1024 * 1024; // 5MB

function handleUpload(req, res) {
  const file = req.files.upload;

  // SECURE: Validate file size
  if (file.size > MAX_SIZE) {
    return res.status(400).json({ error: 'File too large' });
  }

  // SECURE: Validate content type by magic bytes
  const magicBytes = file.data.slice(0, 4).toString('hex');
  const validMagic = ['ffd8ffe0', '89504e47', '47494638']; // JPEG, PNG, GIF
  if (!validMagic.some(m => magicBytes.startsWith(m))) {
    return res.status(400).json({ error: 'Invalid file type' });
  }

  // SECURE: Generate random filename
  const ext = path.extname(file.name).toLowerCase();
  const safeFilename = crypto.randomUUID() + ext;
  const savePath = path.join(UPLOAD_DIR, safeFilename);

  fs.writeFileSync(savePath, file.data);

  res.json({ url: '/uploads/' + safeFilename });
}
                `,
        instructions:
          "Secure the upload: 1) Add MAX_SIZE constant and reject files over 5MB, 2) Validate file type by checking magic bytes (first few bytes), 3) Generate a random filename using crypto.randomUUID() instead of user-provided name, 4) Return appropriate error messages.",
      },
    },
  ],
};
