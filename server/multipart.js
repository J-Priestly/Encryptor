const MAX_BODY = 100 * 1024 * 1024; // 100MB

export function collectBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', chunk => {
      size += chunk.length;
      if (size > MAX_BODY) { req.destroy(); reject(new Error('File too large (100MB max)')); }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

export function parseMultipart(contentType, body) {
  const match = contentType.match(/boundary=(?:"([^"]+)"|([^\s;]+))/);
  if (!match) throw new Error('No boundary found');
  const boundary = match[1] || match[2];
  const boundaryBuf = Buffer.from(`--${boundary}`);

  const fields = {};
  const files = {};
  let start = body.indexOf(boundaryBuf);
  if (start === -1) return { fields, files };

  while (true) {
    start = body.indexOf(boundaryBuf, start);
    if (start === -1) break;
    start += boundaryBuf.length;
    if (body[start] === 0x2d && body[start + 1] === 0x2d) break;
    if (body[start] === 0x0d && body[start + 1] === 0x0a) start += 2;

    const headerEnd = body.indexOf(Buffer.from('\r\n\r\n'), start);
    if (headerEnd === -1) break;

    const headers = body.subarray(start, headerEnd).toString('utf8');
    const dataStart = headerEnd + 4;
    const nextBoundary = body.indexOf(boundaryBuf, dataStart);
    if (nextBoundary === -1) break;
    const dataEnd = nextBoundary - 2;
    const data = body.subarray(dataStart, dataEnd);

    const nameMatch = headers.match(/name="([^"]+)"/);
    const filenameMatch = headers.match(/filename="([^"]+)"/);

    if (nameMatch) {
      if (filenameMatch) {
        files[nameMatch[1]] = { filename: filenameMatch[1], data };
      } else {
        fields[nameMatch[1]] = data.toString('utf8');
      }
    }
    start = nextBoundary;
  }

  return { fields, files };
}
