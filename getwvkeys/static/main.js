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

const widevine_demo_data = {
    license_url: "https://cwip-shaka-proxy.appspot.com/no_auth",
    pssh: "AAAAp3Bzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAAIcSEFF0U4YtQlb9i61PWEIgBNcSEPCTfpp3yFXwptQ4ZMXZ82USEE1LDKJawVjwucGYPFF+4rUSEJAqBRprNlaurBkm/A9dkjISECZHD0KW1F0Eqbq7RC4WmAAaDXdpZGV2aW5lX3Rlc3QiFnNoYWthX2NlYzViZmY1ZGM0MGRkYzlI49yVmwY=",
    headers: "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:106.0) Gecko/20100101 Firefox/106.0",
};

const playready_demo_data = {
    license_url: "https://test.playready.microsoft.com/service/rightsmanager.asmx?cfg=(persist:false,sl:2000)",
    pssh: "AAADfHBzc2gAAAAAmgTweZhAQoarkuZb4IhflQAAA1xcAwAAAQABAFIDPABXAFIATQBIAEUAQQBEAEUAUgAgAHgAbQBsAG4AcwA9ACIAaAB0AHQAcAA6AC8ALwBzAGMAaABlAG0AYQBzAC4AbQBpAGMAcgBvAHMAbwBmAHQALgBjAG8AbQAvAEQAUgBNAC8AMgAwADAANwAvADAAMwAvAFAAbABhAHkAUgBlAGEAZAB5AEgAZQBhAGQAZQByACIAIAB2AGUAcgBzAGkAbwBuAD0AIgA0AC4AMAAuADAALgAwACIAPgA8AEQAQQBUAEEAPgA8AFAAUgBPAFQARQBDAFQASQBOAEYATwA+ADwASwBFAFkATABFAE4APgAxADYAPAAvAEsARQBZAEwARQBOAD4APABBAEwARwBJAEQAPgBBAEUAUwBDAFQAUgA8AC8AQQBMAEcASQBEAD4APAAvAFAAUgBPAFQARQBDAFQASQBOAEYATwA+ADwASwBJAEQAPgA0AFIAcABsAGIAKwBUAGIATgBFAFMAOAB0AEcAawBOAEYAVwBUAEUASABBAD0APQA8AC8ASwBJAEQAPgA8AEMASABFAEMASwBTAFUATQA+AEsATABqADMAUQB6AFEAUAAvAE4AQQA9ADwALwBDAEgARQBDAEsAUwBVAE0APgA8AEwAQQBfAFUAUgBMAD4AaAB0AHQAcABzADoALwAvAHAAcgBvAGYAZgBpAGMAaQBhAGwAcwBpAHQAZQAuAGsAZQB5AGQAZQBsAGkAdgBlAHIAeQAuAG0AZQBkAGkAYQBzAGUAcgB2AGkAYwBlAHMALgB3AGkAbgBkAG8AdwBzAC4AbgBlAHQALwBQAGwAYQB5AFIAZQBhAGQAeQAvADwALwBMAEEAXwBVAFIATAA+ADwAQwBVAFMAVABPAE0AQQBUAFQAUgBJAEIAVQBUAEUAUwA+ADwASQBJAFMAXwBEAFIATQBfAFYARQBSAFMASQBPAE4APgA4AC4AMQAuADIAMwAwADQALgAzADEAPAAvAEkASQBTAF8ARABSAE0AXwBWAEUAUgBTAEkATwBOAD4APAAvAEMAVQBTAFQATwBNAEEAVABUAFIASQBCAFUAVABFAFMAPgA8AC8ARABBAFQAQQA+ADwALwBXAFIATQBIAEUAQQBEAEUAUgA+AA==",
    headers:
        "Content-Type: text/xml; charset=UTF-8\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:106.0) Gecko/20100101 Firefox/106.0",
};

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
    async function server_request_data(endpoint) {
        document.getElementById("status").innerHTML = "Sending Request Through Server";
        const dicted = {
            license_url: document.getElementById("license").value,
            headers: document.getElementById("headers").value,
            pssh: document.getElementById("pssh").value,
            device_hash: document.getElementById("device_hash").value,
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
                Origin: window.location.origin,
                Referer: window.location.href,
            },
            body: JSON.stringify(dicted),
        });
        return await response.text();
    }
    const response = await server_request_data();
    const elem = document.getElementById("status");
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

function deleteWvd(id) {
    const doDelete = confirm("Are you sure you want to delete this WVD?");
    if (!doDelete) return;
    const apiKey = getCookie("api_key");
    fetch(`/me/wvds/${id}`, {
        method: "DELETE",
        headers: {
            Accept: "application/json, text/plain, */*",
            "Content-Type": "application/json",
            "X-API-Key": apiKey,
            Origin: window.location.origin,
            Referer: window.location.href,
        },
    })
        .catch((e) => {
            alert(`Error deleting WVD: ${e}`);
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
            Origin: window.location.origin,
            Referer: window.location.href,
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
const drmSwitch = document.getElementById("drm-switch");
const psshInput = mainForm.querySelector('input[id="pssh"]');
const urlInput = mainForm.querySelector('input[id="license"]');
const headersInput = mainForm.querySelector('textarea[name="headers"]');
const downgradeItem = document.querySelector(".downgrade-item");
const title = document.querySelector(".section-title");

if (drmSwitch) {
    const run = () => {
        const isChecked = drmSwitch.checked;

        if (isChecked) {
            // PlayReady selected
            psshInput.value = playready_demo_data.pssh;
            urlInput.value = playready_demo_data.license_url;
            headersInput.value = playready_demo_data.headers;
            title.innerText = "Get PlayReady Keys";
            if (downgradeItem) downgradeItem.style.display = "flex";
        } else {
            // widevine selected
            psshInput.value = widevine_demo_data.pssh;
            urlInput.value = widevine_demo_data.license_url;
            headersInput.value = widevine_demo_data.headers;
            title.innerText = "Get Widevine Keys";
            if (downgradeItem) downgradeItem.style.display = "none";
        }
    };
    // set initial state to unchecked
    drmSwitch.checked = false; // Default to Widevine
    run(); // refreshing can cause desync
    drmSwitch.addEventListener("change", run);
}
if (keycountElement) keycount();
else console.warn("Keycount Element not found, skipping keycount fetch");

if (formButton) mainForm.addEventListener("submit", handleFormSubmit);
else console.warn("Form Button not found, skipping form submit event listener");
