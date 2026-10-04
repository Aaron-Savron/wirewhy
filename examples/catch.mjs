import { explain, formatReport } from 'wirewhy';

try {
  await fetch('http://127.0.0.1:1');
} catch (error) {
  console.error(formatReport(explain(error, { url: 'http://127.0.0.1:1' })));
}
