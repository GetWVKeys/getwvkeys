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
    server_request();
}

async function keycount() {
    async function key_count() {
        const apiKey = getCookie("api_key");
        const response = await fetch("/count", {
            method: "GET",
            headers: {
                "X-API-Key": apiKey,
            },
        });
        return await response.text();
    }
    const key_count_value = await key_count();
    keycountElement.innerText = key_count_value;
}

function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(";").shift();
}

async function server_request() {
    async function server_request_data() {
        document.getElementById("demo").innerHTML = "Sending Request Through Server";
        const dicted = {
            license_url: document.getElementById("license").value,
            headers: document.getElementById("headers").value,
            pssh: document.getElementById("pssh").value,
            buildInfo: document.getElementById("buildInfo").value,
            proxy: document.getElementById("proxy").value,
            force: document.getElementById("force").checked,
            is_web: true,
        };
        const apiKey = getCookie("api_key");
        const response = await fetch("/api", {
            method: "POST",
            headers: {
                Accept: "application/json, text/plain, */*",
                "Content-Type": "application/json",
                "X-API-Key": apiKey,
            },
            body: JSON.stringify(dicted),
        });
        return await response.text();
    }
    const response = await server_request_data();
    const elem = document.getElementById("demo");
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

function deleteCdm(id) {
    const doDelete = confirm("Are you sure you want to delete this CDM?");
    if (!doDelete) return;
    const apiKey = getCookie("api_key");
    fetch(`/me/cdms/${id}`, {
        method: "DELETE",
        headers: {
            Accept: "application/json, text/plain, */*",
            "Content-Type": "application/json",
            "X-API-Key": apiKey,
        },
    })
        .catch((e) => {
            alert(`Error deleting CDM: ${e}`);
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

function deletePrd(id) {
    const doDelete = confirm("Are you sure you want to delete this PRD?");
    if (!doDelete) return;
    const apiKey = getCookie("api_key");
    fetch(`/me/prds/${id}`, {
        method: "DELETE",
        headers: {
            Accept: "application/json, text/plain, */*",
            "Content-Type": "application/json",
            "X-API-Key": apiKey,
        },
    })
        .catch((e) => {
            alert(`Error deleting PRD: ${e}`);
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

const keycountElement = document.getElementById("keycount");
const mainForm = document.querySelector(".form-container>form");
const formButton = mainForm.querySelector('input[type="submit"]');
const psshInput = mainForm.querySelector('input[id="pssh"]');
const urlInput = mainForm.querySelector('input[id="license"]');
const headersInput = mainForm.querySelector('textarea[name="headers"]');
const downgradeItem = document.querySelector(".downgrade-item");

const queryString = window.location.search;
const urlParams = new URLSearchParams(queryString);
const drm = urlParams.get("drm");

if (psshInput && urlInput && headersInput && downgradeItem) {
    if (!drm || drm.toLowerCase() === "playready") {
        // default to PR
        downgradeItem.style.display = "flex";
    } else if (drm.toLowerCase() === "widevine") {
        // add widevine examples
        psshInput.defaultValue =
            "AAAAp3Bzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAAIcSEFF0U4YtQlb9i61PWEIgBNcSEPCTfpp3yFXwptQ4ZMXZ82USEE1LDKJawVjwucGYPFF+4rUSEJAqBRprNlaurBkm/A9dkjISECZHD0KW1F0Eqbq7RC4WmAAaDXdpZGV2aW5lX3Rlc3QiFnNoYWthX2NlYzViZmY1ZGM0MGRkYzlI49yVmwY=";
        urlInput.defaultValue = "https://cwip-shaka-proxy.appspot.com/no_auth";
        headersInput.defaultValue =
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:106.0) Gecko/20100101 Firefox/106.0";
        downgradeItem.style.display = "none";
    }
}

if (keycountElement) keycount();
else console.warn("Keycount Element not found, skipping keycount fetch");

if (formButton) mainForm.addEventListener("submit", handleFormSubmit);
else console.warn("Form Button not found, skipping form submit event listener");
