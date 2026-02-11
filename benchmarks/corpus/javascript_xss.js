/**
 * Benchmark corpus: JavaScript XSS vulnerabilities.
 */
var userData = "<img src=x onerror=alert(1)>";

// VULN: innerHTML
element.innerHTML = userData;

// VULN: outerHTML
element.outerHTML = userData;

// VULN: document-write
document.write(userData);

// VULN: insertAdjacentHTML
element.insertAdjacentHTML("beforeend", userData);

// SAFE: innerHTML
element.textContent = userData;

// SAFE: outerHTML
var safe = document.createElement("span");
safe.textContent = userData;

// SAFE: document-write
console.log(userData);

// SAFE: insertAdjacentHTML
element.appendChild(document.createTextNode(userData));

// --- React XSS ---

// VULN: dangerouslySetInnerHTML
var component = React.createElement("div", { dangerouslySetInnerHTML: { __html: userData } });

// SAFE: dangerouslySetInnerHTML
var component = React.createElement("div", {}, userData);
