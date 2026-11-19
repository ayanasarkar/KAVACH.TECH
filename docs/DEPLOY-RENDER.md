# Deploying KAVACH on Render

One Docker service runs the console and, inside the same container, the bundled vulnerable lab. The lab listens on
loopback only, so the console can scan it (target `127.0.0.1`) while the internet cannot reach it.

## What the deployment needs

| Variable | Required | Notes |
| :--- | :--- | :--- |
| `KAVACH_ADMIN_USER` | yes | 3-32 characters: lower-case letters, digits, dot, dash, underscore; start with a letter or digit. |
| `KAVACH_ADMIN_PASSWORD` | yes | At least 10 characters. Used only while no account exists. There is no browser setup on a hosted copy: that page only works from the machine itself. |
| `VAPT_ALLOWED_HOSTS` | no | Only for a custom domain, for example `demo.example.com` (no `https://`). Render passes the service's own `<name>.onrender.com` host name to the app, and the console answers on it without any setting. |
| `VAPT_LAB_ONLY` | recommended (`1` is the image default) | Refuses `allow_non_lab` and `authorized_domains`, so the hosted copy can only be pointed at private or loopback lab targets. |
| `VAPT_OPENAI_URL` | optional | For Groq or another OpenAI-compatible model: `https://api.groq.com/openai/v1`. It must end in `/v1`: the program adds `/chat/completions` itself. |
| `VAPT_OPENAI_KEY` | with `VAPT_OPENAI_URL` | Your Groq key. A secret: type it in the dashboard only. |
| `VAPT_MODEL` | with `VAPT_OPENAI_URL` | The exact model id from your Groq account, for example `openai/gpt-oss-120b`. Pick one that your key lists at `https://api.groq.com/openai/v1/models`. |
| `ANTHROPIC_API_KEY` | optional, instead of the three above | For Claude. If it is set, Claude is used and the OpenAI-compatible settings are ignored, so leave it unset when using Groq. With no model settings at all the agent runs on its rules engine. |
| `VAPT_RUN_LAB` | optional | `1` (default) starts the lab inside the container; `0` runs the console alone. |

`.env.example` lists every variable. The program reads real environment variables only; it does not load a `.env` file.

## Steps

1. Push the branch you want to deploy (`finale-prep`) to GitHub.
2. render.com > **New +** > **Web Service** > connect the GitHub repo.
3. **Branch** `finale-prep`. **Language/Runtime** Docker. **Region** Singapore. **Instance type** Free for testing, Starter for a live demo.
4. **Environment Variables**: add `KAVACH_ADMIN_USER`, `KAVACH_ADMIN_PASSWORD`, `VAPT_LAB_ONLY=1` and, for the model, `VAPT_OPENAI_URL`, `VAPT_OPENAI_KEY` and `VAPT_MODEL`.
5. **Advanced > Health Check Path**: `/healthz`.
6. **Create Web Service**. The first build installs nmap and compiles the Go code, so allow several minutes. Wait for **Live**.
7. Open the URL Render shows (`https://<name>.onrender.com`). If a page says "unexpected Host header" (for example on a custom domain), add `VAPT_ALLOWED_HOSTS=<that host name>`; saving redeploys.
8. Go to the console and sign in with the admin user and password from step 4. The start-up banner in the Render logs should name your model (`openai-compatible:...`), not `rules-only`.
9. Check it: run an assessment against `127.0.0.1` and confirm the plan, approvals and PDF work. Or from your machine:
   `$env:SMOKE_USER="..."; $env:SMOKE_PASS="..."; go run ./cmd/smoke -url https://<name>.onrender.com`

## Know before you demo

- **Sleep.** A Free service spins down after 15 minutes without traffic and takes about a minute to wake. Open the URL a few minutes before presenting, or use Starter.
- **Nothing persists on Free.** Assessments, raw output and audit logs live on the container's disk and are lost on every restart, redeploy or spin-down. Download the PDF straight after a run. The admin account is recreated from the environment on each start.
- **Your data leaves the container.** With a hosted model (Groq here), prompts and scan data are sent to that provider. The console and the report flag this. Say so if a judge asks.
- **Lab-only means lab-only.** `VAPT_LAB_ONLY=1` makes the hosted copy refuse public targets, including an organiser-provided domain. Scan those from a local copy, or turn lab-only off knowingly, with a long admin password.
- **Tools.** nmap and nikto are installed when the base image provides them. The console reports any missing tool under the report's limitations, so check the integration matrix before claiming a tool ran live.
- **Exposure.** Anyone who can reach the URL can try to sign in. Use a long password. Keep `VAPT_LAB_ONLY=1`: it is what stops a signed-in user from registering a public target.
- **Big files.** `cmd/vapt/web` is compiled into the binary and copied into the image. Keep videos and audio small (a few MB) or host them elsewhere. GitHub rejects files over 100 MB.
- **Rollback.** In Render, open the service > **Events** or **Deploys** and redeploy an earlier commit.

## What was tested

Compiled with the Dockerfile's build flags and started through `scripts/render-start.sh` with the same environment. A request with an unknown Host is refused, the configured host and the health check work, the session cookie is `Secure` behind an HTTPS proxy, lab-only mode refuses a wider scope, and the full smoke test passes against that instance. The Docker image itself and `render.yaml` were not built or validated against Render.
