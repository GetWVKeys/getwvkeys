/*
 *  This file is part of the GetWVKeys project (https://github.com/GetWVKeys/getwvkeys)
 *  Copyright (C) 2022-2024 Notaghost, Puyodead1 and GetWVKeys contributors
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Affero General Public License as published
 *  by the Free Software Foundation, version 3 of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Affero General Public License for more details.
 *
 *  You should have received a copy of the GNU Affero General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

function handleFormSubmit(event) {
    event.preventDefault();
    formButton.disabled = true;
    formButton.value = "Sending...";
    doRequest();
}

function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(";").shift();
}

async function doRequest() {
    async function doPost() {
        document.getElementById("container-text").innerHTML = "Sending Request...";
        const apiKey = getCookie("api_key");
        const response = await fetch("/wv", {
            method: "POST",
            headers: {
                Accept: "application/json, text/plain, */*",
                "Content-Type": "application/json",
                "X-API-Key": apiKey,
            },
            body: JSON.stringify({
                license_url: document.getElementById("license").value,
                headers: document.getElementById("headers").value,
                pssh: document.getElementById("pssh").value,
                device_code: document.getElementById("deviceCode").value,
                proxy: document.getElementById("proxy").value,
                force: document.getElementById("force").checked,
            }),
        });
        return await response.text();
    }
    const response = await doPost();
    const elem = document.getElementById("container-text");
    setInnerHTML(elem, response);

    formButton.disabled = false;
    formButton.value = "Send";
}

const setInnerHTML = function (elm, html) {
    elm.innerHTML = html;
    Array.from(elm.querySelectorAll("script")).forEach((oldScript) => {
        const newScript = document.createElement("script");
        Array.from(oldScript.attributes).forEach((attr) => newScript.setAttribute(attr.name, attr.value));
        newScript.appendChild(document.createTextNode(oldScript.innerHTML));
        oldScript.parentNode.replaceChild(newScript, oldScript);
    });
};

function parseUnixTimestamp(timestamp) {
    const date = new Date(timestamp * 1000);
    return date.toLocaleString();
}

function deleteDevice(code) {
    const isConfirmed = confirm("Are you sure you want to delete this device?");
    if (!isConfirmed) return;
    const apiKey = getCookie("api_key");
    fetch(`/me/devices/${code}`, {
        method: "DELETE",
        headers: {
            Accept: "application/json, text/plain, */*",
            "Content-Type": "application/json",
            "X-API-Key": apiKey,
        },
    })
        .catch((e) => {
            alert(`Error deleting device: ${e}`);
        })
        .then(async (r) => {
            const text = await r.json();
            if (!r.ok) alert(`An error occurred: ${text.message}`);
            else {
                alert(text.message);
                location.reload();
            }
        });
}

// --------- Main --------- //

const DEFAULT_USER_AGENT =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36";
const mainForm = document.querySelector(".form-container>form");
const formButton = mainForm.querySelector('input[type="submit"]');

mainForm.addEventListener("submit", handleFormSubmit);

// wait until page is loaded
document.addEventListener("DOMContentLoaded", () => {
    const headersBox = document.getElementById("headers");
    headersBox.innerText = `User-Agent: ${navigator.userAgent ?? DEFAULT_USER_AGENT}`;
});
