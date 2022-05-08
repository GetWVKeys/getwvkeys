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


async function server_request() {
  async function server_request_data() {
    document.getElementById('demo').innerHTML =
      'Sending Request Through Server';
    const dicted = {
      password: document.getElementById('pswd').value,
      license: document.getElementById('license').value,
      headers: document.getElementById('headers').value,
      pssh: document.getElementById('pssh').value,
      buildInfo: document.getElementById('buildInfo').value,
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
