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
      'Searching the database';

    const response = await fetch('/findpssh', {
      method: 'POST',
      headers: {
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body: document.getElementById('pssh').value,
    });
    return await response.text();
  }
  const response = await server_request_data();
  document.getElementById('demo').innerHTML = response;

  formButton.disabled = false;
  formButton.value = 'Send';
}
