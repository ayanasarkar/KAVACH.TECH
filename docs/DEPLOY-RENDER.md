# Deploying KAVACH on Render

One Docker service runs the console and, inside the same container, the bundled vulnerable lab. The lab listens on
loopback only, so the console can scan it (target `127.0.0.1`) while the internet cannot reach it.

## What the deployment needs

| Variable | Required | Notes |
| :--- | :--- | :--- |
| `KAVACH_ADMIN_USER` | yes | 3-32 characters: lower-case letters, digits, dot, dash, underscore; start with a letter or digit. |
| `KAVACH_ADMIN_PASSWORD` | yes | At least 10 characters. Used only while no account exists. There is no browser setup on a hosted copy: that page only works from the machine itself. |
| `VAPT_ALLOWED_HOSTS` | yes, after the first deploy | Your service's host name, for example `kavach-ab12.onrender.com` (no `https://`). Without it every request gets "unexpected Host header". |
| `VAPT_LAB_ONLY` | recommended (`1` is the image default) | Refuses `allow_non_lab` and `authorized_domains`, so the hosted copy can only be pointed at private or loopback lab targets. |
| `ANTHROPIC_API_KEY` | optional | Without it the agent runs on its rules engine. A secret: type it in the dashboard only. |
| `VAPT_MODEL` | optional | Defaults to `claude-sonnet-5-5`. |
| `VAPT_RUN_LAB` | optional | `1` (default) starts the lab inside the container; `0` runs the console alone. |

`.env.example` lists every variable. The program reads real environment variables only; it does not load a `.env` file.

## Steps

1. Push the branch you want to deploy (`finale-prep`) to GitHub.
2. render.com > **New +** > **Web Service** > connect the GitHub repo.
3. **Branch** `finale-prep`. **Language/Runtime** Docker. **Region** Singapore. **Instance type** Free for testing, Starter for a live demo.
4. **Environment Variables**: add `KAVACH_ADMIN_USER`, `KAVACH_ADMIN_PASSWORD`, `VAPT_LAB_ONLY=1` and, if you want Claude, `ANTHROPIC_API_KEY`.
5. **Advanced > Health Check Path**: `/healthz`.
6. **Create Web Service**. The first build installs nmap and compiles the Go code, so allow several minutes. Wait for **Live**.
7. Copy the URL Render shows (`https://<name>.onrender.com`). Add `VAPT_ALLOWED_HOSTS=<name>.onrender.com`; saving redeploys.
8. Open the URL, go to the console, sign in with the admin user and password from step 4.
9. Check it: run an assessment against `127.0.0.1` and confirm the plan, approvals and PDF work. Or from your machine:
   `$env:SMOKE_USER="..."; $env:SMOKE_PASS="..."; go run ./cmd/smoke -url https://<name>.onrender.com`

## Know before you demo

- **Sleep.** A Free service spins down after 15 minutes without traffic and takes about a minute to wake. Open the URL a few minutes before presenting, or use Starter.
- **Nothing persists on Free.** Assessments, raw output and audit logs live on the container's disk and are lost on every restart, redeploy or spin-down. Download the PDF straight after a run. The admin account is recreated from the environment on each start.
- **Tools.** nmap and nikto are installed when the base image provides them. The console reports any missing tool under the report's limitations, so check the integration matrix before claiming a tool ran live.
- **Exposure.** Anyone who can reach the URL can try to sign in. Use a long password. Keep `VAPT_LAB_ONLY=1`: it is what stops a signed-in user from registering a public target.
- **Big files.** `cmd/vapt/web` is compiled into the binary and copied into the image. Keep videos and audio small (a few MB) or host them elsewhere. GitHub rejects files over 100 MB.
- **Rollback.** In Render, open the service > **Events** or **Deploys** and redeploy an earlier commit.

## What was tested

Compiled with the Dockerfile's build flags and started through `scripts/render-start.sh` with the same environment. A request with an unknown Host is refused, the configured host and the health check work, the session cookie is `Secure` behind an HTTPS proxy, lab-only mode refuses a wider scope, and the full smoke test passes against that instance. The Docker image itself and `render.yaml` were not built or validated against Render.
