import random
import logging
import subprocess
import sys
import os
import re
import time
import asyncio
import sqlite3
from dotenv import load_dotenv
from datetime import datetime, timezone
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, ContextTypes
from telegram.constants import ParseMode

# Load environment variables
load_dotenv()

# Configuration from .env
TOKEN = os.getenv('TELEGRAM_TOKEN', 'TELEGRAM_BOT_TOKEN')  # Changed from TOKEN to TELEGRAM_TOKEN
ADMIN_ID = int(os.getenv('ADMIN_ID', 0))  # Admin user ID for checks
BOT_STATUS_NAME = os.getenv('BOT_STATUS_NAME', 'UnixNodes')
WATERMARK = os.getenv('WATERMARK', 'Powered by UnixNodes VPS Bot')
# VPS Defaults from .env
DEFAULT_RAM = os.getenv('DEFAULT_RAM', '2g')  # e.g., '2g', '4G'
DEFAULT_CPU = os.getenv('DEFAULT_CPU', '1')  # Lowered default to '1' to avoid common errors
DEFAULT_DISK = os.getenv('DEFAULT_DISK', '10G')  # e.g., '20G' - Note: Disk limit not enforced in container
VPS_HOSTNAME = os.getenv('VPS_HOSTNAME', 'unix-free')  # Base hostname, append user ID
SERVER_LIMIT = int(os.getenv('SERVER_LIMIT', 1))
TOTAL_SERVER_LIMIT = int(os.getenv('TOTAL_SERVER_LIMIT', 50))  # Global total running server limit
DATABASE_FILE = os.getenv('DATABASE_FILE', 'vps_bot.db')

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('vps_bot.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

def is_admin(user_id):
    return user_id == ADMIN_ID

# Database setup with SQLite3
def init_db():
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    default_ram = DEFAULT_RAM
    default_cpu = DEFAULT_CPU
    default_disk = DEFAULT_DISK
    sql = f'''
        CREATE TABLE IF NOT EXISTS vps (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            container_id TEXT UNIQUE NOT NULL,
            container_name TEXT NOT NULL,
            os_type TEXT NOT NULL,
            hostname TEXT NOT NULL,
            status TEXT DEFAULT 'stopped',
            ssh_command TEXT,
            ram TEXT DEFAULT '{default_ram}',
            cpu TEXT DEFAULT '{default_cpu}',
            disk TEXT DEFAULT '{default_disk}',
            suspended INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (user_id)
        )
    '''
    cursor.execute(sql)
    cursor.execute("PRAGMA table_info(vps)")
    columns = [col[1] for col in cursor.fetchall()]
    if 'suspended' not in columns:
        cursor.execute("ALTER TABLE vps ADD COLUMN suspended INTEGER DEFAULT 0")
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS bans (
            user_id INTEGER PRIMARY KEY
        )
    ''')
    conn.commit()
    conn.close()

init_db()

def get_db_connection():
    conn = sqlite3.connect(DATABASE_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def add_user(user_id, username):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('INSERT OR IGNORE INTO users (user_id, username) VALUES (?, ?)', (user_id, username))
    conn.commit()
    conn.close()

def add_ban(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('INSERT OR IGNORE INTO bans (user_id) VALUES (?)', (user_id,))
    conn.commit()
    conn.close()

def remove_ban(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM bans WHERE user_id = ?', (user_id,))
    conn.commit()
    conn.close()

def is_banned(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT 1 FROM bans WHERE user_id = ?', (user_id,))
    banned = cursor.fetchone() is not None
    conn.close()
    return banned

def add_vps(user_id, container_id, container_name, os_type, hostname, ssh_command, ram=DEFAULT_RAM, cpu=DEFAULT_CPU, disk=DEFAULT_DISK):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO vps (user_id, container_id, container_name, os_type, hostname, status, ssh_command, ram, cpu, disk, suspended)
        VALUES (?, ?, ?, ?, ?, 'running', ?, ?, ?, ?, 0)
    ''', (user_id, container_id, container_name, os_type, hostname, ssh_command, ram, cpu, disk))
    conn.commit()
    conn.close()

def get_user_vps(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM vps WHERE user_id = ? ORDER BY created_at DESC', (user_id,))
    vps_list = cursor.fetchall()
    conn.close()
    return vps_list

def count_user_vps(user_id):
    return len(get_user_vps(user_id))

def get_vps_by_container_id(container_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM vps WHERE container_id = ?', (container_id,))
    vps = cursor.fetchone()
    conn.close()
    return vps

def get_vps_by_identifier(user_id, identifier):
    vps_list = get_user_vps(user_id)
    if not identifier:
        return vps_list[0] if vps_list else None
    identifier_lower = identifier.lower()
    for vps in vps_list:
        if (identifier_lower in vps['container_id'].lower() or
            identifier_lower in vps['container_name'].lower()):
            return vps
    return None

def update_vps_status(container_id, status):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('UPDATE vps SET status = ? WHERE container_id = ?', (status, container_id))
    conn.commit()
    conn.close()

def update_vps_ssh(container_id, ssh_command):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('UPDATE vps SET ssh_command = ? WHERE container_id = ?', (ssh_command, container_id))
    conn.commit()
    conn.close()

def update_vps_suspended(container_id, suspended):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('UPDATE vps SET suspended = ? WHERE container_id = ?', (suspended, container_id))
    conn.commit()
    conn.close()

def delete_vps(container_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM vps WHERE container_id = ?', (container_id,))
    conn.commit()
    conn.close()

def get_total_instances():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT COUNT(*) FROM vps WHERE status = "running"')
    count = cursor.fetchone()[0]
    conn.close()
    return count

def parse_gb(resource_str):
    match = re.match(r'(\d+(?:\.\d+)?)([mMgG])?', resource_str.lower())
    if match:
        num = float(match.group(1))
        unit = match.group(2) or 'g'
        if unit in ['g', '']:
            return num
        elif unit in ['m']:
            return num / 1024.0
    return 0.0

def get_uptime(container_id):
    try:
        output = subprocess.check_output(["docker", "inspect", "-f", "{{.State.StartedAt}}", container_id], stderr=subprocess.STDOUT).decode().strip()
        if output == "<no value>":
            return "Not running"
        start_time = datetime.fromisoformat(output.replace('Z', '+00:00'))
        now = datetime.now(timezone.utc)
        uptime = now - start_time
        days = uptime.days
        hours, remainder = divmod(uptime.seconds, 3600)
        minutes, _ = divmod(remainder, 60)
        return f"{days}d {hours}h {minutes}m"
    except Exception as e:
        logger.error(f"Uptime error for {container_id}: {e}")
        return "Unknown"

def get_stats(container_id):
    try:
        output = subprocess.check_output([
            "docker", "stats", "--no-stream", "--format",
            "{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}",
            container_id
        ], stderr=subprocess.STDOUT).decode().strip()
        parts = output.split('\t')
        if len(parts) == 3:
            cpu, mem, net = parts
            return {'cpu': cpu, 'mem': mem, 'net': net}
    except Exception as e:
        logger.error(f"Stats error for {container_id}: {e}")
    return {'cpu': 'N/A', 'mem': 'N/A', 'net': 'N/A'}

def get_logs(container_id, lines=50):
    try:
        output = subprocess.check_output(["docker", "logs", "--tail", str(lines), container_id], stderr=subprocess.STDOUT).decode()
        return output[-2000:]  # Truncate for Telegram limit
    except Exception as e:
        logger.error(f"Logs error for {container_id}: {e}")
        return "Failed to fetch logs"

# Async Docker helpers
async def async_docker_run(image, hostname, ram, cpu, disk, container_name):
    cmd = [
        "docker", "run", "-d",
        "--privileged", "--cap-add=ALL",
        "--restart", "unless-stopped",
        f"--memory={ram}",
        f"--cpus={cpu}",
        f"--hostname={hostname}",
        f"--name={container_name}",
        image,
        "tail", "-f", "/dev/null"
    ]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60.0)
        if proc.returncode != 0:
            logger.error(f"Docker run failed: {stderr.decode()}")
            return None
        return stdout.decode().strip()
    except asyncio.TimeoutError:
        logger.error("Docker run timed out")
        return None
    except Exception as e:
        logger.error(f"Docker run error: {e}")
        return None

async def async_docker_start(container_id):
    try:
        proc = await asyncio.create_subprocess_exec(
            "docker", "start", container_id,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL
        )
        await asyncio.wait_for(proc.communicate(), timeout=30.0)
        return proc.returncode == 0
    except asyncio.TimeoutError:
        logger.warning(f"Docker start timeout for {container_id}")
        return False
    except Exception as e:
        logger.error(f"Docker start error for {container_id}: {e}")
        return False

async def async_docker_stop(container_id):
    try:
        proc = await asyncio.create_subprocess_exec(
            "docker", "stop", container_id,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL
        )
        await asyncio.wait_for(proc.communicate(), timeout=30.0)
        return proc.returncode == 0
    except asyncio.TimeoutError:
        logger.warning(f"Docker stop timeout for {container_id}")
        try:
            await asyncio.create_subprocess_exec("docker", "kill", container_id, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL).communicate()
        except:
            pass
        return False
    except Exception as e:
        logger.error(f"Docker stop error for {container_id}: {e}")
        return False

async def async_docker_restart(container_id):
    try:
        proc = await asyncio.create_subprocess_exec(
            "docker", "restart", container_id,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL
        )
        await asyncio.wait_for(proc.communicate(), timeout=30.0)
        return proc.returncode == 0
    except asyncio.TimeoutError:
        logger.warning(f"Docker restart timeout for {container_id}")
        return False
    except Exception as e:
        logger.error(f"Docker restart error for {container_id}: {e}")
        return False

async def async_docker_rm(container_id):
    try:
        proc = await asyncio.create_subprocess_exec(
            "docker", "rm", "-f", container_id,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL
        )
        await proc.communicate()
        return proc.returncode == 0
    except Exception as e:
        logger.error(f"Docker rm error for {container_id}: {e}")
        return False

async def async_install_tmate(container_id, os_type):
    install_cmd = "apt-get update && apt-get install -y tmate curl wget sudo openssh-client"
    try:
        proc = await asyncio.create_subprocess_exec(
            "docker", "exec", container_id, "bash", "-c", install_cmd,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE
        )
        _, stderr = await asyncio.wait_for(proc.communicate(), timeout=120.0)
        if proc.returncode != 0:
            logger.warning(f"Tmate install warning for {container_id}: {stderr.decode()}")
        else:
            logger.info(f"Tmate installed in {container_id}")
    except asyncio.TimeoutError:
        logger.error(f"Tmate install timeout for {container_id}")
    except Exception as e:
        logger.error(f"Failed to install tmate in {container_id}: {e}")

# SSH capture
async def capture_ssh_session_line(process):
    while True:
        try:
            output = await asyncio.wait_for(process.stdout.readline(), timeout=30.0)
            if not output:
                break
            output = output.decode('utf-8').strip()
            if "ssh session:" in output.lower():
                return output.split("ssh session:")[-1].strip()
        except asyncio.TimeoutError:
            break
    return None

async def docker_exec_tmate(container_id):
    try:
        exec_cmd = await asyncio.create_subprocess_exec(
            "docker", "exec", container_id, "tmate", "-F",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        return exec_cmd
    except Exception as e:
        logger.error(f"Tmate exec failed: {e}")
        return None

# Generic regen SSH
async def regen_ssh_command(update: Update, context: ContextTypes.DEFAULT_TYPE, vps_identifier, target_user_id=None):
    if target_user_id is None:
        target_user_id = update.effective_user.id
    
    vps = get_vps_by_identifier(target_user_id, vps_identifier)
    if not vps:
        await update.message.reply_text("No active VPS found.", parse_mode=ParseMode.HTML)
        return False
    
    if vps['status'] != "running":
        await update.message.reply_text("VPS must be running to generate SSH.", parse_mode=ParseMode.HTML)
        return False
    
    container_id = vps['container_id']
    exec_process = await docker_exec_tmate(container_id)
    
    if exec_process:
        ssh_line = await capture_ssh_session_line(exec_process)
        if ssh_line:
            update_vps_ssh(container_id, ssh_line)
            message = f"<b>New SSH Session Generated</b>\n\n<code>{ssh_line}</code>\n\n{WATERMARK}"
            try:
                await update.message.reply_text(message, parse_mode=ParseMode.HTML)
            except Exception as e:
                logger.error(f"Failed to send message: {e}")
            return True
        else:
            await update.message.reply_text("Failed to generate SSH session.", parse_mode=ParseMode.HTML)
            return False
    else:
        await update.message.reply_text("Failed to execute tmate.", parse_mode=ParseMode.HTML)
        return False

# Start/Stop/Restart helpers
async def manage_vps(update: Update, context: ContextTypes.DEFAULT_TYPE, vps_identifier, action, target_user_id=None):
    if target_user_id is None:
        target_user_id = update.effective_user.id
    
    vps = get_vps_by_identifier(target_user_id, vps_identifier)
    if not vps:
        await update.message.reply_text("No VPS found.", parse_mode=ParseMode.HTML)
        return
    
    if action == "start" and vps['suspended'] and target_user_id == update.effective_user.id:
        await update.message.reply_text("This VPS is suspended by an admin. Contact support.", parse_mode=ParseMode.HTML)
        return
    
    container_id = vps['container_id']
    os_type = vps['os_type']
    success = False
    
    if action == "start":
        success = await async_docker_start(container_id)
        if success:
            update_vps_status(container_id, "running")
    elif action == "stop":
        success = await async_docker_stop(container_id)
        if success:
            update_vps_status(container_id, "stopped")
    elif action == "restart":
        success = await async_docker_restart(container_id)
        if success:
            update_vps_status(container_id, "running")
    
    if success:
        os_name = "Ubuntu 22.04" if os_type == "ubuntu" else "Debian 12"
        message = f"<b>VPS {action.title()}ed Successfully</b>\n\nOS: {os_name}\n{WATERMARK}"
        
        if action in ["start", "restart"]:
            regen_success = await regen_ssh_command(update, context, vps_identifier, target_user_id)
            if regen_success:
                message += "\nNew SSH session generated."
            else:
                message += "\nFailed to generate new SSH session."
        
        await update.message.reply_text(message, parse_mode=ParseMode.HTML)
    else:
        await update.message.reply_text(f"Failed to {action} the VPS.", parse_mode=ParseMode.HTML)

# Reinstall helper
async def reinstall_vps(update: Update, context: ContextTypes.DEFAULT_TYPE, vps_identifier, os_type, target_user_id=None):
    if target_user_id is None:
        target_user_id = update.effective_user.id
    
    vps = get_vps_by_identifier(target_user_id, vps_identifier)
    if not vps:
        await update.message.reply_text("No VPS found.", parse_mode=ParseMode.HTML)
        return
    
    container_id = vps['container_id']
    user_id = vps['user_id']
    hostname = vps['hostname']
    ram, cpu, disk = vps['ram'], vps['cpu'], vps['disk']
    
    # Stop and remove
    await async_docker_stop(container_id)
    await asyncio.sleep(2)
    await async_docker_rm(container_id)
    delete_vps(container_id)
    
    # Create new with unique name
    suffix = random.randint(1000, 9999)
    new_container_name = f"{os_type}-vps-{user_id}-{suffix}"
    image = "ubuntu:22.04" if os_type == "ubuntu" else "debian:bookworm"
    new_container_id = await async_docker_run(image, hostname, ram, cpu, disk, new_container_name)
    
    if new_container_id:
        await async_install_tmate(new_container_id, os_type)
        await asyncio.sleep(10)  # Wait longer for install
        exec_process = await docker_exec_tmate(new_container_id)
        ssh_line = await capture_ssh_session_line(exec_process)
        
        if ssh_line:
            add_vps(user_id, new_container_id, new_container_name, os_type, hostname, ssh_line, ram, cpu, disk)
            os_name = "Ubuntu 22.04" if os_type == "ubuntu" else "Debian 12"
            message = f"<b>VPS Reinstalled Successfully</b>\n\nOS: {os_name}\n<code>{ssh_line}</code>\n\n{WATERMARK}"
            await update.message.reply_text(message, parse_mode=ParseMode.HTML)
        else:
            await update.message.reply_text("Reinstall failed: Unable to generate SSH.", parse_mode=ParseMode.HTML)
            await async_docker_rm(new_container_id)
    else:
        await update.message.reply_text("Reinstall failed: Docker creation error.", parse_mode=ParseMode.HTML)

# Create VPS helper
async def create_vps(update: Update, context: ContextTypes.DEFAULT_TYPE, os_type, ram=DEFAULT_RAM, cpu=DEFAULT_CPU, disk=DEFAULT_DISK, target_user_id=None):
    if target_user_id is None:
        target_user_id = update.effective_user.id
        user = update.effective_user
    else:
        user = await context.bot.get_chat(target_user_id)
    
    username = user.username or user.first_name or str(user.id)
    add_user(target_user_id, username)
    
    if is_banned(target_user_id):
        await update.message.reply_text("You are banned from creating VPS instances.", parse_mode=ParseMode.HTML)
        return
    
    if count_user_vps(target_user_id) >= SERVER_LIMIT:
        await update.message.reply_text(f"You have reached the limit of {SERVER_LIMIT} VPS instances.", parse_mode=ParseMode.HTML)
        return
    
    if get_total_instances() >= TOTAL_SERVER_LIMIT:
        await update.message.reply_text(f"Global server limit reached: {TOTAL_SERVER_LIMIT} total running instances.", parse_mode=ParseMode.HTML)
        return
    
    await update.message.reply_text("Creating your VPS instance...", parse_mode=ParseMode.HTML)
    
    hostname = f"{VPS_HOSTNAME}-{target_user_id}"
    suffix = random.randint(1000, 9999)
    container_name = f"{os_type}-vps-{target_user_id}-{suffix}"
    image = "ubuntu:22.04" if os_type == "ubuntu" else "debian:bookworm"
    container_id = await async_docker_run(image, hostname, ram, cpu, disk, container_name)
    
    if not container_id:
        await update.message.reply_text("Failed to create Docker container.", parse_mode=ParseMode.HTML)
        return
    
    await asyncio.sleep(5)  # Wait for container to start
    await async_install_tmate(container_id, os_type)
    await asyncio.sleep(10)  # Wait for install
    
    exec_process = await docker_exec_tmate(container_id)
    ssh_line = await capture_ssh_session_line(exec_process)
    
    if ssh_line:
        add_vps(target_user_id, container_id, container_name, os_type, hostname, ssh_line, ram, cpu, disk)
        os_name = "Ubuntu 22.04" if os_type == "ubuntu" else "Debian 12"
        message = f"""<b>VPS Instance Created</b>

OS: {os_name}
RAM: {ram} | CPU: {cpu} | Disk: {disk}

<code>{ssh_line}</code>

{WATERMARK}"""
        await update.message.reply_text(message, parse_mode=ParseMode.HTML)
    else:
        await update.message.reply_text("Creation failed: Unable to generate SSH session.", parse_mode=ParseMode.HTML)
        await async_docker_stop(container_id)
        await asyncio.sleep(2)
        await async_docker_rm(container_id)

# Telegram Bot Commands
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        f"Welcome to {BOT_STATUS_NAME} VPS Bot!\nUse /help to see available commands.",
        parse_mode=ParseMode.HTML
    )

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    help_text = f"""<b>{BOT_STATUS_NAME} VPS Bot - Commands</b>

<b>User Commands:</b>
/deploy - Deploy a new VPS
/list - List your VPS instances
/vpsinfo - View VPS details
/start - Start a VPS
/stop - Stop a VPS
/restart - Restart a VPS
/regen - Regenerate SSH session
/reinstall - Reinstall VPS with new OS
/remove - Remove a VPS
/logs - View VPS logs
/about - Bot information
/ping - Check bot latency

<b>Admin Commands:</b>
/admincreate - Create VPS for user
/adminmanage - Manage user's VPS
/adminlist - List all VPS instances
/adminusers - List users with VPS counts
/adminstats - View bot statistics
/adminban - Ban a user
/adminunban - Unban a user
/adminkillall - Stop all running VPS
/admindeleteuser - Delete all VPS for user

{WATERMARK}"""
    
    await update.message.reply_text(help_text, parse_mode=ParseMode.HTML)

async def deploy_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        keyboard = [
            [
                InlineKeyboardButton("Ubuntu", callback_data="deploy_ubuntu"),
                InlineKeyboardButton("Debian", callback_data="deploy_debian")
            ]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await update.message.reply_text(
            "Choose OS for your VPS:",
            reply_markup=reply_markup
        )
        return
    
    os_type = context.args[0].lower()
    if os_type not in ["ubuntu", "debian"]:
        await update.message.reply_text("Invalid OS. Use 'ubuntu' or 'debian'.", parse_mode=ParseMode.HTML)
        return
    
    await create_vps(update, context, os_type)

async def list_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    vps_list = get_user_vps(update.effective_user.id)
    if not vps_list:
        await update.message.reply_text("You have no VPS instances.", parse_mode=ParseMode.HTML)
        return
    
    message = f"<b>Your VPS Instances</b>\n\n"
    for vps in vps_list[:10]:  # Limit to 10 for readability
        status_emoji = "🟢" if vps['status'] == "running" else "🔴"
        uptime = get_uptime(vps['container_id'])
        suspended_text = " (Suspended)" if vps['suspended'] else ""
        message += f"""<b>{status_emoji} {vps['container_name']} ({vps['os_type']}){suspended_text}</b>
ID: <code>{vps['container_id']}</code>
Hostname: {vps['hostname']}
Status: {vps['status']}
Uptime: {uptime}
Resources: {vps['ram']} RAM | {vps['cpu']} CPU | {vps['disk']} Disk

"""
    
    message += f"\n{WATERMARK}"
    await update.message.reply_text(message, parse_mode=ParseMode.HTML)

async def vpsinfo_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    identifier = ' '.join(context.args) if context.args else None
    vps = get_vps_by_identifier(update.effective_user.id, identifier)
    
    if not vps:
        await update.message.reply_text("No VPS found.", parse_mode=ParseMode.HTML)
        return
    
    container_id = vps['container_id']
    uptime = get_uptime(container_id)
    stats = get_stats(container_id)
    os_name = "Ubuntu 22.04" if vps['os_type'] == "ubuntu" else "Debian 12"
    
    message = f"""<b>VPS Details: {vps['container_name']}</b>

<b>OS:</b> {os_name}
<b>Hostname:</b> {vps['hostname']}
<b>Status:</b> {vps['status']}
<b>Suspended:</b> {'Yes' if vps['suspended'] else 'No'}
<b>Container ID:</b> <code>{container_id}</code>
<b>Allocated Resources:</b> {vps['ram']} RAM | {vps['cpu']} CPU | {vps['disk']} Disk
<b>Current Usage:</b> CPU: {stats['cpu']} | Mem: {stats['mem']}
<b>Uptime:</b> {uptime}
<b>Network I/O:</b> {stats['net']}
<b>Created At:</b> {vps['created_at']}"""
    
    if vps['ssh_command']:
        ssh_trunc = vps['ssh_command'][:100] + "..." if len(vps['ssh_command']) > 100 else vps['ssh_command']
        message += f"\n\n<b>SSH Command:</b> <code>{ssh_trunc}</code>"
    
    message += f"\n\n{WATERMARK}"
    await update.message.reply_text(message, parse_mode=ParseMode.HTML)

async def regen_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    identifier = ' '.join(context.args) if context.args else None
    await regen_ssh_command(update, context, identifier)

async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    identifier = ' '.join(context.args) if context.args else None
    await manage_vps(update, context, identifier, "start")

async def stop_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    identifier = ' '.join(context.args) if context.args else None
    await manage_vps(update, context, identifier, "stop")

async def restart_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    identifier = ' '.join(context.args) if context.args else None
    await manage_vps(update, context, identifier, "restart")

async def reinstall_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Usage: /reinstall <vps_identifier> <ubuntu|debian>", parse_mode=ParseMode.HTML)
        return
    
    args = context.args
    if len(args) < 2:
        await update.message.reply_text("Usage: /reinstall <vps_identifier> <ubuntu|debian>", parse_mode=ParseMode.HTML)
        return
    
    identifier = args[0]
    os_type = args[1].lower()
    
    if os_type not in ["ubuntu", "debian"]:
        await update.message.reply_text("Invalid OS. Use 'ubuntu' or 'debian'.", parse_mode=ParseMode.HTML)
        return
    
    await reinstall_vps(update, context, identifier, os_type)

async def remove_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    identifier = ' '.join(context.args) if context.args else None
    vps = get_vps_by_identifier(update.effective_user.id, identifier)
    
    if not vps:
        await update.message.reply_text("VPS not found.", parse_mode=ParseMode.HTML)
        return
    
    container_id = vps['container_id']
    await async_docker_stop(container_id)
    await asyncio.sleep(2)
    await async_docker_rm(container_id)
    delete_vps(container_id)
    
    await update.message.reply_text(f"VPS removed successfully.\n\n{WATERMARK}", parse_mode=ParseMode.HTML)

async def logs_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Usage: /logs <vps_identifier> [lines]", parse_mode=ParseMode.HTML)
        return
    
    identifier = context.args[0]
    lines = int(context.args[1]) if len(context.args) > 1 else 50
    
    vps = get_vps_by_identifier(update.effective_user.id, identifier)
    if not vps:
        await update.message.reply_text("VPS not found.", parse_mode=ParseMode.HTML)
        return
    
    container_id = vps['container_id']
    logs = get_logs(container_id, lines)
    
    message = f"<b>Logs for {vps['container_name']}</b>\n\n<code>{logs}</code>\n\n{WATERMARK}"
    await update.message.reply_text(message, parse_mode=ParseMode.HTML)

async def about_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    about_text = f"""<b>🤖 VPS Manager Bot • About</b>

<b>A powerful, fast, and user-friendly Telegram bot for managing VPS servers and Docker containers.</b>

Designed with <b>speed</b>, <b>stability</b>, <b>security</b>, and <b>simplicity</b> in mind 🚀🔒
Perfect for server admins, developers, and hosting enthusiasts!

<b>📌 Bot Information</b>
• <b>Name:</b> VPS Manager Bot
• <b>Version:</b> v1.0
• <b>Framework:</b> Python • python-telegram-bot
• <b>Features:</b> VPS control, Docker management, real-time monitoring

<b>👨‍💻 Developer • Hopingboyz</b>
Passionate Full-Stack Developer and DevOps Enthusiast

<b>🔗 Connect:</b>
• YouTube: @Hopingboyz
• GitHub: Hopingboyz
• Instagram: @hopingboyz

<b>Built with ❤️ and ☕ by Hopingboyz</b>
Thank you for using VPS Manager Bot!"""
    
    await update.message.reply_text(about_text, parse_mode=ParseMode.HTML)

async def ping_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    start_time = time.time()
    message = await update.message.reply_text("Pinging...")
    end_time = time.time()
    
    latency = round((end_time - start_time) * 1000, 2)
    await message.edit_text(f"🏓 Pong!\nLatency: {latency}ms\n\n{WATERMARK}")

# Admin Commands
async def admin_create_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.effective_user.id):
        await update.message.reply_text("This command is restricted to admins only.", parse_mode=ParseMode.HTML)
        return
    
    if len(context.args) < 2:
        await update.message.reply_text(
            "Usage: /admincreate <user_id> <ubuntu|debian> [ram] [cpu] [disk]",
            parse_mode=ParseMode.HTML
        )
        return
    
    try:
        target_user_id = int(context.args[0])
        os_type = context.args[1].lower()
        ram = context.args[2] if len(context.args) > 2 else DEFAULT_RAM
        cpu = context.args[3] if len(context.args) > 3 else DEFAULT_CPU
        disk = context.args[4] if len(context.args) > 4 else DEFAULT_DISK
        
        if os_type not in ["ubuntu", "debian"]:
            await update.message.reply_text("Invalid OS. Use 'ubuntu' or 'debian'.", parse_mode=ParseMode.HTML)
            return
        
        await create_vps(update, context, os_type, ram, cpu, disk, target_user_id)
    except ValueError:
        await update.message.reply_text("Invalid user ID.", parse_mode=ParseMode.HTML)

async def admin_manage_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.effective_user.id):
        await update.message.reply_text("This command is restricted to admins only.", parse_mode=ParseMode.HTML)
        return
    
    if len(context.args) < 3:
        await update.message.reply_text(
            "Usage: /adminmanage <user_id> <vps_identifier> <start|stop|restart|delete|suspend|unsuspend>",
            parse_mode=ParseMode.HTML
        )
        return
    
    try:
        target_user_id = int(context.args[0])
        identifier = context.args[1]
        action = context.args[2].lower()
        
        if action not in ["start", "stop", "restart", "delete", "suspend", "unsuspend"]:
            await update.message.reply_text(
                "Invalid action. Use: start, stop, restart, delete, suspend, unsuspend",
                parse_mode=ParseMode.HTML
            )
            return
        
        vps = get_vps_by_identifier(target_user_id, identifier)
        if not vps:
            await update.message.reply_text("VPS not found for this user.", parse_mode=ParseMode.HTML)
            return
        
        container_id = vps['container_id']
        success = False
        
        if action == "delete":
            await async_docker_stop(container_id)
            await asyncio.sleep(2)
            await async_docker_rm(container_id)
            delete_vps(container_id)
            success = True
            msg = f"Deleted VPS for user {target_user_id}"
        elif action in ["start", "stop", "restart"]:
            if action == "start":
                success = await async_docker_start(container_id)
                update_vps_status(container_id, "running")
            elif action == "stop":
                success = await async_docker_stop(container_id)
                update_vps_status(container_id, "stopped")
            elif action == "restart":
                success = await async_docker_restart(container_id)
                update_vps_status(container_id, "running")
            msg = f"{action.title()}ed VPS for user {target_user_id}"
        elif action == "suspend":
            success = await async_docker_stop(container_id)
            if success:
                update_vps_status(container_id, "stopped")
                update_vps_suspended(container_id, 1)
            msg = f"Suspended VPS for user {target_user_id}"
        elif action == "unsuspend":
            update_vps_suspended(container_id, 0)
            success = True
            msg = f"Unsuspended VPS for user {target_user_id}"
        
        if success:
            await update.message.reply_text(f"<b>Admin Action Completed</b>\n\n{msg}\n\n{WATERMARK}", parse_mode=ParseMode.HTML)
        else:
            await update.message.reply_text("Action failed.", parse_mode=ParseMode.HTML)
            
    except ValueError:
        await update.message.reply_text("Invalid user ID.", parse_mode=ParseMode.HTML)

async def admin_list_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.effective_user.id):
        await update.message.reply_text("This command is restricted to admins only.", parse_mode=ParseMode.HTML)
        return
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT u.username, v.container_id, v.container_name, v.os_type, v.hostname, v.status, v.ram, v.cpu, v.disk, v.suspended
        FROM vps v JOIN users u ON v.user_id = u.user_id
        ORDER BY v.created_at DESC
    ''')
    all_vps = cursor.fetchall()
    conn.close()
    
    if not all_vps:
        await update.message.reply_text("No VPS instances found.", parse_mode=ParseMode.HTML)
        return
    
    message = "<b>All VPS Instances</b>\n\n"
    for row in all_vps[:15]:  # Limit to 15 for readability
        username = row['username']
        container_id = row['container_id']
        container_name = row['container_name']
        os_type = row['os_type']
        hostname = row['hostname']
        status = row['status']
        ram = row['ram']
        cpu = row['cpu']
        disk = row['disk']
        suspended = row['suspended']
        status_emoji = "🟢" if status == "running" else "🔴"
        suspended_text = " (Suspended)" if suspended else ""
        
        message += f"""<b>{status_emoji} {username} - {container_name} ({os_type}){suspended_text}</b>
ID: <code>{container_id}</code>
Hostname: {hostname}
Status: {status}
Resources: {ram} RAM | {cpu} CPU | {disk} Disk

"""
    
    message += f"\n{WATERMARK}"
    await update.message.reply_text(message, parse_mode=ParseMode.HTML)

async def admin_users_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.effective_user.id):
        await update.message.reply_text("This command is restricted to admins only.", parse_mode=ParseMode.HTML)
        return
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT u.username, COUNT(v.id) as total_vps,
               SUM(CASE WHEN v.status = 'running' THEN 1 ELSE 0 END) as running_vps
        FROM users u LEFT JOIN vps v ON u.user_id = v.user_id
        GROUP BY u.user_id, u.username
        ORDER BY total_vps DESC
    ''')
    users = cursor.fetchall()
    conn.close()
    
    if not users:
        await update.message.reply_text("No users found.", parse_mode=ParseMode.HTML)
        return
    
    message = "<b>Users Overview</b>\n\n"
    for row in users[:20]:
        username = row['username']
        total = row['total_vps']
        running = row['running_vps'] or 0
        message += f"<b>{username}</b>\nTotal VPS: {total} | Running: {running}\n\n"
    
    message += f"{WATERMARK}"
    await update.message.reply_text(message, parse_mode=ParseMode.HTML)

async def admin_stats_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.effective_user.id):
        await update.message.reply_text("This command is restricted to admins only.", parse_mode=ParseMode.HTML)
        return
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT COUNT(*) FROM users')
    num_users = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM vps')
    num_vps = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM vps WHERE status="running"')
    num_running = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM bans')
    num_banned = cursor.fetchone()[0]
    cursor.execute('SELECT ram, cpu, disk FROM vps WHERE status="running"')
    rows = cursor.fetchall()
    total_cpu = sum(float(row['cpu']) for row in rows)
    total_ram = sum(parse_gb(row['ram']) for row in rows)
    total_disk = sum(parse_gb(row['disk']) for row in rows)
    conn.close()
    
    message = f"""<b>Bot Statistics</b>

<b>Total Users:</b> {num_users}
<b>Banned Users:</b> {num_banned}
<b>Total VPS:</b> {num_vps}
<b>Running VPS:</b> {num_running}
<b>Total CPU Allocated:</b> {total_cpu} cores
<b>Total RAM Allocated:</b> {total_ram:.1f} GB
<b>Total Disk Allocated:</b> {total_disk:.1f} GB

{WATERMARK}"""
    
    await update.message.reply_text(message, parse_mode=ParseMode.HTML)

async def admin_ban_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.effective_user.id):
        await update.message.reply_text("This command is restricted to admins only.", parse_mode=ParseMode.HTML)
        return
    
    if not context.args:
        await update.message.reply_text("Usage: /adminban <user_id>", parse_mode=ParseMode.HTML)
        return
    
    try:
        target_user_id = int(context.args[0])
        add_ban(target_user_id)
        await update.message.reply_text(f"Banned user {target_user_id} from creating VPS instances.\n\n{WATERMARK}", parse_mode=ParseMode.HTML)
    except ValueError:
        await update.message.reply_text("Invalid user ID.", parse_mode=ParseMode.HTML)

async def admin_unban_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.effective_user.id):
        await update.message.reply_text("This command is restricted to admins only.", parse_mode=ParseMode.HTML)
        return
    
    if not context.args:
        await update.message.reply_text("Usage: /adminunban <user_id>", parse_mode=ParseMode.HTML)
        return
    
    try:
        target_user_id = int(context.args[0])
        remove_ban(target_user_id)
        await update.message.reply_text(f"Unbanned user {target_user_id}.\n\n{WATERMARK}", parse_mode=ParseMode.HTML)
    except ValueError:
        await update.message.reply_text("Invalid user ID.", parse_mode=ParseMode.HTML)

async def admin_killall_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.effective_user.id):
        await update.message.reply_text("This command is restricted to admins only.", parse_mode=ParseMode.HTML)
        return
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT container_id FROM vps WHERE status = "running"')
    running = cursor.fetchall()
    conn.close()
    
    stopped = 0
    for row in running:
        cid = row['container_id']
        if await async_docker_stop(cid):
            update_vps_status(cid, "stopped")
            stopped += 1
            logger.info(f"Stopped {cid}")
    
    await update.message.reply_text(
        f"<b>Admin: Kill All Running VPS</b>\n\nSuccessfully stopped {stopped} running VPS instances.\n\n{WATERMARK}",
        parse_mode=ParseMode.HTML
    )

async def admin_deleteuser_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.effective_user.id):
        await update.message.reply_text("This command is restricted to admins only.", parse_mode=ParseMode.HTML)
        return
    
    if not context.args:
        await update.message.reply_text("Usage: /admindeleteuser <user_id>", parse_mode=ParseMode.HTML)
        return
    
    try:
        target_user_id = int(context.args[0])
        vps_list = get_user_vps(target_user_id)
        deleted = 0
        
        for vps in vps_list:
            container_id = vps['container_id']
            await async_docker_stop(container_id)
            await asyncio.sleep(2)
            await async_docker_rm(container_id)
            delete_vps(container_id)
            deleted += 1
            logger.info(f"Deleted VPS {container_id} for user {target_user_id}")
        
        await update.message.reply_text(
            f"Deleted {deleted} VPS instances for user {target_user_id}.\n\n{WATERMARK}",
            parse_mode=ParseMode.HTML
        )
    except ValueError:
        await update.message.reply_text("Invalid user ID.", parse_mode=ParseMode.HTML)

async def button_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    
    if query.data.startswith("deploy_"):
        os_type = query.data.split("_")[1]
        await create_vps(update, context, os_type)

# Status sync task
async def sync_statuses(context: ContextTypes.DEFAULT_TYPE):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT container_id, status FROM vps')
    for row in cursor.fetchall():
        cid = row['container_id']
        stat = row['status']
        try:
            out = subprocess.check_output(["docker", "inspect", "-f", "{{.State.Status}}", cid]).decode().strip()
            if out != stat:
                update_vps_status(cid, out)
                logger.info(f"Updated status of {cid} to {out}")
        except subprocess.CalledProcessError:
            if stat != "stopped":
                update_vps_status(cid, "stopped")
                logger.info(f"Updated non-existent {cid} to stopped")
        except Exception as e:
            logger.error(f"Status sync error for {cid}: {e}")
    conn.close()

def main():
    if not TOKEN:
        logger.error("TELEGRAM_TOKEN not set in .env")
        sys.exit(1)
    
    application = Application.builder().token(TOKEN).build()
    
    # Add command handlers
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(CommandHandler("deploy", deploy_command))
    application.add_handler(CommandHandler("list", list_command))
    application.add_handler(CommandHandler("vpsinfo", vpsinfo_command))
    application.add_handler(CommandHandler("regen", regen_command))
    application.add_handler(CommandHandler("start", start_command))
    application.add_handler(CommandHandler("stop", stop_command))
    application.add_handler(CommandHandler("restart", restart_command))
    application.add_handler(CommandHandler("reinstall", reinstall_command))
    application.add_handler(CommandHandler("remove", remove_command))
    application.add_handler(CommandHandler("logs", logs_command))
    application.add_handler(CommandHandler("about", about_command))
    application.add_handler(CommandHandler("ping", ping_command))
    
    # Admin commands
    application.add_handler(CommandHandler("admincreate", admin_create_command))
    application.add_handler(CommandHandler("adminmanage", admin_manage_command))
    application.add_handler(CommandHandler("adminlist", admin_list_command))
    application.add_handler(CommandHandler("adminusers", admin_users_command))
    application.add_handler(CommandHandler("adminstats", admin_stats_command))
    application.add_handler(CommandHandler("adminban", admin_ban_command))
    application.add_handler(CommandHandler("adminunban", admin_unban_command))
    application.add_handler(CommandHandler("adminkillall", admin_killall_command))
    application.add_handler(CommandHandler("admindeleteuser", admin_deleteuser_command))
    
    # Callback query handler
    application.add_handler(CallbackQueryHandler(button_callback))
    
    # Add job queue for status sync
    job_queue = application.job_queue
    if job_queue:
        job_queue.run_repeating(sync_statuses, interval=300, first=10)  # Every 5 minutes
    
    logger.info("Bot starting...")
    application.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == "__main__":
    main()
