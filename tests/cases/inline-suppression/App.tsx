export function load() {
  // rnsec-ignore: INSECURE_HTTP_URL legacy partner endpoint, tracked in SEC-12
  fetch('http://partner.example-corp.com/a');
  fetch('http://partner.example-corp.com/b');
  fetch('http://partner.example-corp.com/c'); // rnsec-ignore: NO_REQUEST_TIMEOUT
}
