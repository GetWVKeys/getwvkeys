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
    document.getElementById("keycount").innerText = key_count_value;
}

async function generating_request() {
    async function genrating_license_request() {
        document.getElementById("demo").innerHTML = "Generating License Request";
        const dicted = {
            pssh: document.getElementById("pssh").value,
            buildInfo: document.getElementById("buildInfo").value,
        };
        const apiKey = getCookie("api_key");
        const response = await fetch("/pssh", {
            method: "POST",
            headers: {
                Accept: "application/json, text/plain, */*",
                "Content-Type": "application/json",
                "X-API-Key": apiKey,
            },
            body: JSON.stringify(dicted),
        });
        if (!response.ok) {
            alert("Wrong PSSH/BUILDINFO");
            throw new FatalError("Something went badly wrong!");
        }
        return await response.arrayBuffer();
    }

    async function get_headers() {
        document.getElementById("demo").innerHTML = "Generating Headers";
        const dicted = {
            headers: document.getElementById("headers").value,
        };
        const apiKey = getCookie("api_key");
        const response = await fetch("/headers", {
            method: "POST",
            headers: {
                Accept: "application/json, text/plain, */*",
                "Content-Type": "application/json",
                "X-API-Key": apiKey,
            },
            body: JSON.stringify(dicted),
        });
        if (!response.ok) {
            alert("WRONG HEADERS");
            throw new FatalError("Something went badly wrong!");
        }
        return await response.text();
    }

    async function post_license_request(genrated_request, headers) {
        document.getElementById("demo").innerHTML = "Sending Post License Request";
        const posturl = document.getElementById("license").value;
        headers = JSON.parse(headers);
        headers["Content-Type"] = "application/x-www-form-urlencoded";
        headers["Origin"] = posturl;
        headers["Referer"] = posturl;
        const response = await fetch(posturl, {
            method: "POST",
            headers: headers,
            body: genrated_request,
        });
        if (!response.ok) {
            alert("WRONG SENDING LICENSE REQUEST ");
            throw new FatalError("Something went badly wrong!");
        }
        return await response.arrayBuffer();
    }
    async function decrypt_response(license_response, headers) {
        license_response_base64String = btoa(String.fromCharCode.apply(null, new Uint8Array(license_response)));
        const dicted = {
            license_response: license_response_base64String,
            license_url: document.getElementById("license").value,
            headers: headers,
            pssh: document.getElementById("pssh").value,
            buildInfo: document.getElementById("buildInfo").value,
        };
        const apiKey = getCookie("api_key");
        const response = await fetch("/decrypter", {
            method: "POST",
            headers: {
                Accept: "application/json, text/plain, */*",
                "Content-Type": "application/json",
                "X-API-Key": apiKey,
            },
            body: JSON.stringify(dicted),
        });
        if (!response.ok) {
            alert("ERROR DECRYPTION / WRONG RESPONSE / JSONED RESPONSE");
            document.getElementById("demo").innerHTML = license_response;
            throw new FatalError("Something went badly wrong!");
        }
        return await response.text();
    }
    const genrated_request = await genrating_license_request();
    document.getElementById("demo").innerHTML = "License Request Generated";
    const headers = await get_headers();
    document.getElementById("demo").innerHTML = "Headers Corrected";
    const license_response = await post_license_request(genrated_request, headers);
    document.getElementById("demo").innerHTML = "Decrypting Content";
    const content_keys = await decrypt_response(license_response, headers);
    document.getElementById("demo").innerHTML = content_keys;
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
        };
        const apiKey = getCookie("api_key");
        const response = await fetch("/wv", {
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

keycount();

const mainForm = document.querySelector(".form-container>form");
const formButton = mainForm.querySelector('input[type="submit"]');

mainForm.addEventListener("submit", handleFormSubmit);
