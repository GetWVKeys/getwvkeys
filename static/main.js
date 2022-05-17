const mainForm = document.querySelector('.form-container>form');
const formButton = mainForm.querySelector('input[type="submit"]');

mainForm.addEventListener('submit', handleFormSubmit);

function handleFormSubmit(event) {
  event.preventDefault();
  formButton.disabled = true;
  formButton.value = 'Sending...';
  server_request();
}

async function keycount() {
  async function key_count() {
    const response = await fetch('/count', {
      method: 'GET',
      headers: {},
    });
    return await response.text();
  }
  const key_count_value = await key_count();
  document.getElementById('key-count').innerText = key_count_value;
}
keycount();

async function generating_request() {
  async function genrating_license_request() {
    document.getElementById('demo').innerHTML = 'Generating License Request';
    const dicted = {
      pssh: document.getElementById('pssh').value,
      buildInfo: document.getElementById('buildInfo').value,
    };
    const response = await fetch('/pssh', {
      method: 'POST',
      headers: {
        Accept: 'application/json, text/plain, */*',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(dicted),
    });
    if (!response.ok) {
      alert('Wrong PSSH/BUILDINFO');
      throw new FatalError('Something went badly wrong!');
    }
    return await response.arrayBuffer();
  }

  async function get_headers() {
    document.getElementById('demo').innerHTML = 'Generating Headers';
    const dicted = {
      headers: document.getElementById('headers').value,
    };
    const response = await fetch('/headers', {
      method: 'POST',
      headers: {
        Accept: 'application/json, text/plain, */*',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(dicted),
    });
    if (!response.ok) {
      alert('WRONG HEADERS');
      throw new FatalError('Something went badly wrong!');
    }
    return await response.text();
  }

  async function post_license_request(genrated_request, headers) {
    document.getElementById('demo').innerHTML = 'Sending Post License Request';
    const posturl = document.getElementById('license').value;
    headers = JSON.parse(headers);
    headers['Content-Type'] = 'application/x-www-form-urlencoded';
    headers['Origin'] = posturl;
    headers['Referer'] = posturl;
    const response = await fetch(posturl, {
      method: 'POST',
      headers: headers,
      body: genrated_request,
    });
    if (!response.ok) {
      alert('WRONG SENDING LICENSE REQUEST ');
      throw new FatalError('Something went badly wrong!');
    }
    return await response.arrayBuffer();
  }
  async function decrypt_response(license_response, headers) {
    license_response_base64String = btoa(
      String.fromCharCode.apply(null, new Uint8Array(license_response))
    );
    const dicted = {
      license_response: license_response_base64String,
      license: document.getElementById('license').value,
      headers: headers,
      pssh: document.getElementById('pssh').value,
      buildInfo: document.getElementById('buildInfo').value,
    };
    const response = await fetch('/decrypter', {
      method: 'POST',
      headers: {
        Accept: 'application/json, text/plain, */*',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(dicted),
    });
    if (!response.ok) {
      alert('ERROR DECRYPTION / WRONG RESPONSE / JSONED RESPONSE');
      document.getElementById('demo').innerHTML = license_response;
      throw new FatalError('Something went badly wrong!');
    }
    return await response.text();
  }
  const genrated_request = await genrating_license_request();
  document.getElementById('demo').innerHTML = 'License Request Generated';
  const headers = await get_headers();
  document.getElementById('demo').innerHTML = 'Headers Corrected';
  const license_response = await post_license_request(
    genrated_request,
    headers
  );
  document.getElementById('demo').innerHTML = 'Decrypting Content';
  const content_keys = await decrypt_response(license_response, headers);
  document.getElementById('demo').innerHTML = content_keys;
}

async function server_request() {
  async function server_request_data() {
    document.getElementById('demo').innerHTML =
      'Sending Request Through Server';
    const dicted = {
      license: document.getElementById('license').value,
      headers: document.getElementById('headers').value,
      pssh: document.getElementById('pssh').value,
      buildInfo: document.getElementById('buildInfo').value,
      proxy: document.getElementById('proxy').value,
      cache: document.getElementById('cache').checked,
    };
    const response = await fetch('/wv', {
      method: 'POST',
      headers: {
        Accept: 'application/json, text/plain, */*',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(dicted),
    });
    return await response.text();
  }
  const response = await server_request_data();
  document.getElementById('demo').innerHTML = response;

  formButton.disabled = false;
  formButton.value = 'Send';
}
