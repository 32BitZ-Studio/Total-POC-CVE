document.addEventListener("DOMContentLoaded", () => {
  // DOM elements
  const rsyncInput = document.getElementById("rsyncInput");
  const checkButton = document.getElementById("checkButton");
  const generateButton = document.getElementById("generateButton");
  const remoteUrl = document.getElementById("remoteUrl");
  const remoteToken = document.getElementById("remoteToken");
  const remoteScanBtn = document.getElementById("remoteScanBtn");
  const copyFixBtn = document.getElementById("copyFixBtn");
  const exportBtn = document.getElementById("exportBtn");
  const actionButtons = document.getElementById("actionButtons");
  const warningMsg = document.getElementById("warning");
  const localResult = document.getElementById("localResult");
  const localResultContent = document.getElementById("localResultContent");
  const remoteResult = document.getElementById("remoteResult");
  const remoteResultContent = document.getElementById("remoteResultContent");

  let currentFix = "";

  // Input validation
  rsyncInput.addEventListener("input", () => {
    const showWarning = !rsyncInput.value.startsWith("rsync") && rsyncInput.value.length > 0;
    warningMsg.classList.toggle("hidden", !showWarning);
  });

  // Generate safe command
  generateButton.addEventListener("click", () => {
    rsyncInput.value = "rsync -avz --protect-args /local user@host:/remote";
  });

  // Display result function
  const displayResult = (resultElement, contentElement, title, cmd, isSecure, issues, fixedCmd, isRemote = false) => {
    resultElement.className = `result-section ${isRemote ? 'remote-' : 'local-'}${isSecure ? 'safe-result' : 'unsafe-result'}`;
    
    let contentHTML = `
      <div class="result-title">${title}</div>
      <div class="command-display">${cmd}</div>
    `;

    if (!isSecure) {
      contentHTML += `
        <div>Issues found in command:</div>
        <div class="issues-list">
          ${issues.map(issue => `<div>• ${issue}</div>`).join('')}
        </div>
      `;

      if (fixedCmd) {
        currentFix = fixedCmd;
        contentHTML += `
          <div>Suggested Fix:</div>
          <div class="fix-display">${fixedCmd}</div>
        `;
        actionButtons.classList.remove("hidden");
      }
    } else {
      contentHTML += `<div>✅ Command is secure</div>`;
      actionButtons.classList.add("hidden");
    }

    contentElement.innerHTML = contentHTML;
    resultElement.style.display = "block";
  };

  // Local scan function
  const analyzeLocally = (cmd) => {
    if (!cmd.startsWith("rsync")) {
      return {
        secure: false,
        issues: ["Not a valid rsync command."],
        fixed: null
      };
    }

    const hasProtectArgs = cmd.includes("--protect-args");
    const patterns = [/\s-\s/, /;\s*rm\s+-rf/, /&&\s*rm\s+-rf/, /\|\|?\s*rm\s+-rf/, /\$\{.*\}/, /%s/, /`.*`/, /\$\(.*\)/];
    const foundPatterns = patterns.filter(p => p.test(cmd));
    const issues = [];

    if (!hasProtectArgs) {
      issues.push("Missing --protect-args (CVE-2018-5764 risk)");
    }
    if (foundPatterns.length > 0) {
      issues.push(...foundPatterns.map(p => `Dangerous pattern: ${p.source}`));
    }

    return {
      secure: issues.length === 0,
      issues,
      fixed: issues.length > 0 ? `${cmd} --protect-args` : null
    };
  };

  // Local scan button
  checkButton.addEventListener("click", () => {
    const cmd = rsyncInput.value.trim();
    const analysis = analyzeLocally(cmd);
    displayResult(
      localResult,
      localResultContent,
      "Local Scan",
      cmd,
      analysis.secure,
      analysis.issues,
      analysis.fixed,
      false
    );
    remoteResult.style.display = "none";
  });

  // Remote scan button - PURELY SERVER-DEPENDENT
  remoteScanBtn.addEventListener("click", () => {
    const cmd = rsyncInput.value.trim();
    const url = remoteUrl.value.trim();
    const token = remoteToken.value.trim();

    // Clear previous results
    remoteResult.className = "result-section remote-result";
    remoteResultContent.innerHTML = "<div class='loading'>Contacting server to analyze command...</div>";
    remoteResult.style.display = "block";
    actionButtons.classList.add("hidden");

    // Validate inputs
    if (!cmd) {
      remoteResult.className = "result-section unsafe-result";
      remoteResultContent.innerHTML = "❌ Please enter a command to scan";
      return;
    }

    if (!url || !token) {
      remoteResult.className = "result-section unsafe-result";
      remoteResultContent.innerHTML = "❌ Please provide both URL and token for remote scan";
      return;
    }

    // Server request
    fetch(`${url}/api/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token, command: cmd })
    })
    .then(res => {
      if (!res.ok) {
        throw new Error(`Server error: ${res.status} ${res.statusText}`);
      }
      return res.json();
    })
    .then(data => {
      if (!data || typeof data.secure === 'undefined') {
        throw new Error("Invalid server response");
      }
      
      displayResult(
        remoteResult,
        remoteResultContent,
        "Remote Scan",
        cmd,
        data.secure,
        data.details || [],
        data.fixed || null,
        true
      );
    })
    .catch(err => {
      remoteResult.className = "result-section unsafe-result";
      remoteResultContent.innerHTML = `
        ❌ Remote scan failed<br><br>
        <div style="font-size: 0.9em;">
          Error: ${err.message}<br><br>
          <strong>Note:</strong> Remote scanning requires a working server connection.
        </div>
      `;
    });
  });

  // Copy fix button
  copyFixBtn.addEventListener("click", () => {
    if (currentFix) {
      navigator.clipboard.writeText(currentFix).then(() => {
        const originalText = copyFixBtn.textContent;
        copyFixBtn.textContent = "✓ Copied!";
        setTimeout(() => {
          copyFixBtn.textContent = originalText;
        }, 2000);
      });
    }
  });

  // Export button
  exportBtn.addEventListener("click", () => {
    const results = {
      timestamp: new Date().toISOString(),
      command: rsyncInput.value.trim(),
      localScan: {
        status: localResult.style.display === "none" ? "not performed" : 
          localResult.className.includes("safe") ? "secure" : "unsafe",
        issues: localResultContent.textContent.includes("Issues found") ? 
          Array.from(localResultContent.querySelectorAll(".issues-list div")).map(el => el.textContent.replace("• ", "")) : [],
        fixed: localResultContent.querySelector(".fix-display")?.textContent || ""
      },
      remoteScan: {
        status: remoteResult.style.display === "none" ? "not performed" : 
          remoteResult.className.includes("safe") ? "secure" : remoteResultContent.innerHTML.includes("failed") ? "failed" : "unsafe",
        issues: remoteResultContent.textContent.includes("Issues found") ? 
          Array.from(remoteResultContent.querySelectorAll(".issues-list div")).map(el => el.textContent.replace("• ", "")) : [],
        fixed: remoteResultContent.querySelector(".fix-display")?.textContent || "",
        server: remoteUrl.value.trim()
      }
    };

    const blob = new Blob([JSON.stringify(results, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `syncshield_scan_${new Date().toISOString().replace(/[:.]/g, "-")}.json`;
    a.click();
    URL.revokeObjectURL(url);
  });
});