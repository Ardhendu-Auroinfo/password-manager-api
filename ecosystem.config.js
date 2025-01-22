module.exports = {
  apps: [{
    name: "lockdownpass-api",
    script: "index.js",
    cwd: "/home/lockdownpass/public_html/api",
    env: {
      NODE_ENV: "production",
      PORT: 3001
    },
    instances: 1,
    exec_mode: "fork",
    max_memory_restart: "200M",
    error_file: "/home/lockdownpass/logs/api-error.log",
    out_file: "/home/lockdownpass/logs/api-out.log",
    merge_logs: true,
    log_date_format: "YYYY-MM-DD HH:mm:ss Z",
    watch: false,
    autorestart: true
  }]
}