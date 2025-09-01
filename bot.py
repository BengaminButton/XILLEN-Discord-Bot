import discord
from discord.ext import commands, tasks
import asyncio
import json
import datetime
import logging
import os
from typing import Optional, List, Dict
import aiohttp
import sqlite3
from dataclasses import dataclass
from enum import Enum

class SecurityLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class SecurityEvent:
    timestamp: datetime.datetime
    user_id: int
    user_name: str
    event_type: str
    description: str
    level: SecurityLevel
    channel_id: Optional[int] = None
    message_id: Optional[int] = None

class XillenSecurityBot(commands.Bot):
    def __init__(self):
        intents = discord.Intents.default()
        intents.message_content = True
        intents.members = True
        intents.guilds = True
        
        super().__init__(
            command_prefix='!',
            intents=intents,
            help_command=None
        )
        
        self.config = self.load_config()
        self.security_events: List[SecurityEvent] = []
        self.suspicious_users: Dict[int, Dict] = {}
        self.db = Database()
        self.logger = self.setup_logging()
        
        self.add_cog(SecurityCommands(self))
        self.add_cog(ModerationCommands(self))
        self.add_cog(MonitoringCommands(self))
        self.add_cog(AdminCommands(self))
        
    def load_config(self) -> dict:
        try:
            with open('config.json', 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            config = {
                "token": "YOUR_BOT_TOKEN_HERE",
                "owner_id": 123456789,
                "log_channel_id": None,
                "security_level": "medium",
                "auto_moderation": True,
                "suspicious_threshold": 3,
                "welcome_message": True
            }
            with open('config.json', 'w') as f:
                json.dump(config, f, indent=2)
            return config
    
    def setup_logging(self) -> logging.Logger:
        logger = logging.getLogger('XillenSecurityBot')
        logger.setLevel(logging.INFO)
        
        handler = logging.FileHandler('xillen_security.log')
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        
        return logger
    
    async def setup_hook(self):
        await self.db.init()
        self.logger.info("Database initialized")
        
    async def on_ready(self):
        self.logger.info(f'Logged in as {self.user.name} ({self.user.id})')
        print("╔══════════════════════════════════════════════════════════════╗")
        print("║                    XILLEN Security Bot                      ║")
        print("║                        v2.0 by @Bengamin_Button            ║")
        print("╚══════════════════════════════════════════════════════════════╝")
        print(f"Bot is ready! Logged in as {self.user.name}")
        
        await self.change_presence(
            activity=discord.Activity(
                type=discord.ActivityType.watching,
                name="за безопасностью сервера"
            )
        )
        
        self.monitoring_task.start()
    
    async def on_member_join(self, member: discord.Member):
        if self.config.get("welcome_message", True):
            await self.send_welcome_message(member)
        
        await self.check_new_member(member)
        await self.log_security_event(
            SecurityEvent(
                timestamp=datetime.datetime.now(),
                user_id=member.id,
                user_name=member.name,
                event_type="MEMBER_JOIN",
                description=f"New member joined: {member.name}#{member.discriminator}",
                level=SecurityLevel.LOW
            )
        )
    
    async def on_member_remove(self, member: discord.Member):
        await self.log_security_event(
            SecurityEvent(
                timestamp=datetime.datetime.now(),
                user_id=member.id,
                user_name=member.name,
                event_type="MEMBER_LEAVE",
                description=f"Member left: {member.name}#{member.discriminator}",
                level=SecurityLevel.LOW
            )
        )
    
    async def on_message(self, message: discord.Message):
        if message.author.bot:
            return
        
        await self.process_message(message)
        await self.bot.process_commands(message)
    
    async def process_message(self, message: discord.Message):
        content = message.content.lower()
        user_id = message.author.id
        
        if await self.is_suspicious_content(content):
            await self.handle_suspicious_message(message)
            await self.add_suspicion(user_id, "suspicious_content", 1)
        
        if await self.is_spam(message):
            await self.handle_spam(message)
            await self.add_suspicion(user_id, "spam", 2)
        
        if await self.contains_invite(content):
            await self.handle_invite(message)
            await self.add_suspicion(user_id, "invite_link", 3)
        
        await self.log_message_event(message)
    
    async def is_suspicious_content(self, content: str) -> bool:
        suspicious_words = [
            "hack", "cheat", "exploit", "crack", "bypass",
            "ddos", "bot", "script", "auto", "macro"
        ]
        
        return any(word in content for word in suspicious_words)
    
    async def is_spam(self, message: discord.Message) -> bool:
        user_id = message.author.id
        
        if user_id not in self.suspicious_users:
            return False
        
        user_data = self.suspicious_users[user_id]
        recent_messages = user_data.get("recent_messages", [])
        
        now = datetime.datetime.now()
        recent_messages = [msg for msg in recent_messages if (now - msg).seconds < 10]
        
        if len(recent_messages) >= 5:
            return True
        
        recent_messages.append(now)
        user_data["recent_messages"] = recent_messages
        return False
    
    async def contains_invite(self, content: str) -> bool:
        return "discord.gg/" in content or "discordapp.com/invite/" in content
    
    async def handle_suspicious_message(self, message: discord.Message):
        embed = discord.Embed(
            title="⚠️ Подозрительное сообщение",
            description="Обнаружено подозрительное содержимое",
            color=discord.Color.yellow(),
            timestamp=datetime.datetime.now()
        )
        embed.add_field(name="Автор", value=message.author.mention, inline=True)
        embed.add_field(name="Канал", value=message.channel.mention, inline=True)
        embed.add_field(name="Сообщение", value=message.content[:100] + "..." if len(message.content) > 100 else message.content, inline=False)
        
        await self.send_security_alert(embed)
    
    async def handle_spam(self, message: discord.Message):
        embed = discord.Embed(
            title="🚫 Спам обнаружен",
            description="Пользователь отправляет слишком много сообщений",
            color=discord.Color.red(),
            timestamp=datetime.datetime.now()
        )
        embed.add_field(name="Автор", value=message.author.mention, inline=True)
        embed.add_field(name="Канал", value=message.channel.mention, inline=True)
        
        await self.send_security_alert(embed)
        
        if self.config.get("auto_moderation", True):
            await message.author.timeout(datetime.timedelta(minutes=5), reason="Spam detection")
    
    async def handle_invite(self, message: discord.Message):
        embed = discord.Embed(
            title="🔗 Приглашение обнаружено",
            description="Пользователь отправил ссылку-приглашение",
            color=discord.Color.orange(),
            timestamp=datetime.datetime.now()
        )
        embed.add_field(name="Автор", value=message.author.mention, inline=True)
        embed.add_field(name="Канал", value=message.channel.mention, inline=True)
        
        await self.send_security_alert(embed)
        
        if self.config.get("auto_moderation", True):
            await message.delete()
            await message.author.timeout(datetime.timedelta(minutes=10), reason="Invite link")
    
    async def add_suspicion(self, user_id: int, reason: str, points: int):
        if user_id not in self.suspicious_users:
            self.suspicious_users[user_id] = {
                "total_points": 0,
                "reasons": [],
                "recent_messages": []
            }
        
        user_data = self.suspicious_users[user_id]
        user_data["total_points"] += points
        user_data["reasons"].append({
            "reason": reason,
            "points": points,
            "timestamp": datetime.datetime.now()
        })
        
        if user_data["total_points"] >= self.config.get("suspicious_threshold", 3):
            await self.handle_high_suspicion(user_id, user_data)
    
    async def handle_high_suspicion(self, user_id: int, user_data: dict):
        embed = discord.Embed(
            title="🚨 Высокий уровень подозрений",
            description="Пользователь достиг критического уровня подозрений",
            color=discord.Color.dark_red(),
            timestamp=datetime.datetime.now()
        )
        
        user = self.get_user(user_id)
        if user:
            embed.add_field(name="Пользователь", value=user.mention, inline=True)
            embed.add_field(name="Очки подозрений", value=user_data["total_points"], inline=True)
            
            reasons = [r["reason"] for r in user_data["reasons"][-5:]]
            embed.add_field(name="Последние причины", value=", ".join(reasons), inline=False)
        
        await self.send_security_alert(embed)
    
    async def send_security_alert(self, embed: discord.Embed):
        log_channel_id = self.config.get("log_channel_id")
        if log_channel_id:
            try:
                channel = self.get_channel(log_channel_id)
                if channel:
                    await channel.send(embed=embed)
            except Exception as e:
                self.logger.error(f"Failed to send security alert: {e}")
    
    async def log_security_event(self, event: SecurityEvent):
        self.security_events.append(event)
        await self.db.log_event(event)
        
        if len(self.security_events) > 1000:
            self.security_events = self.security_events[-1000:]
    
    async def log_message_event(self, message: discord.Message):
        await self.db.log_message(
            message.id,
            message.author.id,
            message.author.name,
            message.channel.id,
            message.content,
            message.created_at
        )
    
    async def send_welcome_message(self, member: discord.Member):
        embed = discord.Embed(
            title="🎉 Добро пожаловать!",
            description=f"Привет, {member.mention}! Добро пожаловать на сервер!",
            color=discord.Color.green(),
            timestamp=datetime.datetime.now()
        )
        embed.add_field(name="Правила", value="Обязательно ознакомьтесь с правилами сервера!", inline=False)
        embed.add_field(name="Безопасность", value="Наш бот следит за безопасностью сервера", inline=False)
        
        try:
            await member.send(embed=embed)
        except:
            pass
    
    async def check_new_member(self, member: discord.Member):
        account_age = datetime.datetime.now() - member.created_at
        
        if account_age.days < 7:
            embed = discord.Embed(
                title="🆕 Новый аккаунт",
                description="Обнаружен новый аккаунт Discord",
                color=discord.Color.blue(),
                timestamp=datetime.datetime.now()
            )
            embed.add_field(name="Пользователь", value=member.mention, inline=True)
            embed.add_field(name="Возраст аккаунта", value=f"{account_age.days} дней", inline=True)
            
            await self.send_security_alert(embed)
    
    @tasks.loop(minutes=5)
    async def monitoring_task(self):
        await self.perform_security_scan()
    
    async def perform_security_scan(self):
        try:
            for guild in self.guilds:
                await self.scan_guild_security(guild)
        except Exception as e:
            self.logger.error(f"Security scan failed: {e}")
    
    async def scan_guild_security(self, guild: discord.Guild):
        total_members = guild.member_count
        online_members = len([m for m in guild.members if m.status != discord.Status.offline])
        
        if total_members > 0:
            online_percentage = (online_members / total_members) * 100
            
            if online_percentage < 10 and total_members > 100:
                embed = discord.Embed(
                    title="📊 Низкая активность",
                    description="Обнаружена низкая активность на сервере",
                    color=discord.Color.yellow(),
                    timestamp=datetime.datetime.now()
                )
                embed.add_field(name="Сервер", value=guild.name, inline=True)
                embed.add_field(name="Онлайн", value=f"{online_members}/{total_members}", inline=True)
                embed.add_field(name="Процент", value=f"{online_percentage:.1f}%", inline=True)
                
                await self.send_security_alert(embed)

class SecurityCommands(commands.Cog):
    def __init__(self, bot: XillenSecurityBot):
        self.bot = bot
    
    @commands.command(name="security")
    @commands.has_permissions(manage_messages=True)
    async def security_status(self, ctx):
        embed = discord.Embed(
            title="🛡️ Статус безопасности",
            color=discord.Color.blue(),
            timestamp=datetime.datetime.now()
        )
        
        total_events = len(self.bot.security_events)
        suspicious_users = len(self.bot.suspicious_users)
        
        embed.add_field(name="Всего событий", value=total_events, inline=True)
        embed.add_field(name="Подозрительных пользователей", value=suspicious_users, inline=True)
        embed.add_field(name="Уровень безопасности", value=self.bot.config.get("security_level", "medium"), inline=True)
        
        recent_events = self.bot.security_events[-5:] if self.bot.security_events else []
        if recent_events:
            events_text = "\n".join([f"• {e.event_type}: {e.description[:50]}..." for e in recent_events])
            embed.add_field(name="Последние события", value=events_text, inline=False)
        
        await ctx.send(embed=embed)
    
    @commands.command(name="scan")
    @commands.has_permissions(manage_messages=True)
    async def scan_user(self, ctx, member: discord.Member):
        embed = discord.Embed(
            title="🔍 Результат сканирования",
            color=discord.Color.green(),
            timestamp=datetime.datetime.now()
        )
        
        user_data = self.bot.suspicious_users.get(member.id, {})
        total_points = user_data.get("total_points", 0)
        
        embed.add_field(name="Пользователь", value=member.mention, inline=True)
        embed.add_field(name="Очки подозрений", value=total_points, inline=True)
        
        if total_points == 0:
            embed.add_field(name="Статус", value="✅ Безопасен", inline=True)
            embed.color = discord.Color.green()
        elif total_points < 3:
            embed.add_field(name="Статус", value="⚠️ Подозрителен", inline=True)
            embed.color = discord.Color.yellow()
        else:
            embed.add_field(name="Статус", value="🚨 Опасен", inline=True)
            embed.color = discord.Color.red()
        
        if user_data.get("reasons"):
            reasons = [r["reason"] for r in user_data["reasons"][-3:]]
            embed.add_field(name="Последние причины", value=", ".join(reasons), inline=False)
        
        await ctx.send(embed=embed)

class ModerationCommands(commands.Cog):
    def __init__(self, bot: XillenSecurityBot):
        self.bot = bot
    
    @commands.command(name="warn")
    @commands.has_permissions(manage_messages=True)
    async def warn_user(self, ctx, member: discord.Member, *, reason: str = "Не указана"):
        embed = discord.Embed(
            title="⚠️ Предупреждение выдано",
            color=discord.Color.orange(),
            timestamp=datetime.datetime.now()
        )
        embed.add_field(name="Пользователь", value=member.mention, inline=True)
        embed.add_field(name="Модератор", value=ctx.author.mention, inline=True)
        embed.add_field(name="Причина", value=reason, inline=False)
        
        await ctx.send(embed=embed)
        await self.bot.add_suspicion(member.id, "manual_warning", 2)
    
    @commands.command(name="timeout")
    @commands.has_permissions(manage_messages=True)
    async def timeout_user(self, ctx, member: discord.Member, duration: int, *, reason: str = "Не указана"):
        try:
            await member.timeout(datetime.timedelta(minutes=duration), reason=reason)
            
            embed = discord.Embed(
                title="⏰ Таймаут выдан",
                color=discord.Color.red(),
                timestamp=datetime.datetime.now()
            )
            embed.add_field(name="Пользователь", value=member.mention, inline=True)
            embed.add_field(name="Модератор", value=ctx.author.mention, inline=True)
            embed.add_field(name="Длительность", value=f"{duration} минут", inline=True)
            embed.add_field(name="Причина", value=reason, inline=False)
            
            await ctx.send(embed=embed)
            await self.bot.add_suspicion(member.id, "manual_timeout", 3)
            
        except Exception as e:
            await ctx.send(f"❌ Ошибка при выдаче таймаута: {e}")

class MonitoringCommands(commands.Cog):
    def __init__(self, bot: XillenSecurityBot):
        self.bot = bot
    
    @commands.command(name="logs")
    @commands.has_permissions(manage_messages=True)
    async def show_logs(self, ctx, event_type: str = "all", limit: int = 10):
        if limit > 25:
            limit = 25
        
        events = self.bot.security_events
        
        if event_type != "all":
            events = [e for e in events if e.event_type == event_type.upper()]
        
        if not events:
            await ctx.send("📝 Логи не найдены")
            return
        
        embed = discord.Embed(
            title="📋 Логи безопасности",
            color=discord.Color.blue(),
            timestamp=datetime.datetime.now()
        )
        
        recent_events = events[-limit:]
        for event in recent_events:
            embed.add_field(
                name=f"[{event.event_type}] {event.user_name}",
                value=f"{event.description}\nВремя: {event.timestamp.strftime('%H:%M:%S')}",
                inline=False
            )
        
        await ctx.send(embed=embed)
    
    @commands.command(name="stats")
    @commands.has_permissions(manage_messages=True)
    async def show_stats(self, ctx):
        embed = discord.Embed(
            title="📊 Статистика безопасности",
            color=discord.Color.blue(),
            timestamp=datetime.datetime.now()
        )
        
        total_events = len(self.bot.security_events)
        event_types = {}
        
        for event in self.bot.security_events:
            event_types[event.event_type] = event_types.get(event.event_type, 0) + 1
        
        embed.add_field(name="Всего событий", value=total_events, inline=True)
        embed.add_field(name="Подозрительных пользователей", value=len(self.bot.suspicious_users), inline=True)
        
        for event_type, count in sorted(event_types.items(), key=lambda x: x[1], reverse=True)[:5]:
            embed.add_field(name=event_type, value=count, inline=True)
        
        await ctx.send(embed=embed)

class AdminCommands(commands.Cog):
    def __init__(self, bot: XillenSecurityBot):
        self.bot = bot
    
    @commands.command(name="reload")
    @commands.has_permissions(administrator=True)
    async def reload_config(self, ctx):
        self.bot.config = self.bot.load_config()
        await ctx.send("✅ Конфигурация перезагружена")
    
    @commands.command(name="clear_suspicion")
    @commands.has_permissions(administrator=True)
    async def clear_suspicion(self, ctx, member: discord.Member):
        if member.id in self.bot.suspicious_users:
            del self.bot.suspicious_users[member.id]
            await ctx.send(f"✅ Подозрения для {member.mention} очищены")
        else:
            await ctx.send(f"ℹ️ У {member.mention} нет подозрений")

class Database:
    def __init__(self):
        self.db_path = "xillen_security.db"
    
    async def init(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                user_id INTEGER NOT NULL,
                user_name TEXT NOT NULL,
                event_type TEXT NOT NULL,
                description TEXT NOT NULL,
                level TEXT NOT NULL,
                channel_id INTEGER,
                message_id INTEGER
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL,
                user_name TEXT NOT NULL,
                channel_id INTEGER NOT NULL,
                content TEXT NOT NULL,
                timestamp TEXT NOT NULL
            )
        ''')
        
        conn.commit()
        conn.close()
    
    async def log_event(self, event: SecurityEvent):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO security_events 
            (timestamp, user_id, user_name, event_type, description, level, channel_id, message_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            event.timestamp.isoformat(),
            event.user_id,
            event.user_name,
            event.event_type,
            event.description,
            event.level.value,
            event.channel_id,
            event.message_id
        ))
        
        conn.commit()
        conn.close()
    
    async def log_message(self, message_id: int, user_id: int, user_name: str, 
                         channel_id: int, content: str, timestamp: datetime.datetime):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO messages 
            (id, user_id, user_name, channel_id, content, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            message_id,
            user_id,
            user_name,
            channel_id,
            content,
            timestamp.isoformat()
        ))
        
        conn.commit()
        conn.close()

async def main():
    bot = XillenSecurityBot()
    
    try:
        await bot.start(bot.config["token"])
    except discord.LoginFailure:
        print("❌ Неверный токен бота!")
        print("Проверьте файл config.json и убедитесь, что токен указан правильно.")
    except Exception as e:
        print(f"❌ Ошибка запуска бота: {e}")

if __name__ == "__main__":
    asyncio.run(main())

