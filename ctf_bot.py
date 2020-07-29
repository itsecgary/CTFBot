import discord
import os
from discord.ext import commands, tasks
from itertools import cycle
from config_vars import *
import help_info

################################ DATA STRUCTURES ###############################
bot = commands.Bot(command_prefix = '>')
bot.remove_command('help')

#status = cycle(['making challenges', 'getting mad... jk', 'calculating points'])
extensions = ['competitions', 'rankings', 'ctftime', 'ctf']

#################################### EVENTS ####################################
@bot.event # Startup duties
async def on_ready():
    print("-------------------------------")
    print(f"{bot.user.name} - Online")
    print(f"discord.py {discord.__version__}")
    print("-------------------------------")
    await bot.change_presence(status=discord.Status.online, activity=discord.Game(name=">help"))

    # Create current member info
    for guild in bot.guilds:
        server = client[str(guild.name).replace(' ', '-')]
        member_cnt = 0
        for member in guild.members:
            members = server['members']
            member_info = {
                "name": member.name + '#' + member.discriminator,
                "points": 0,
                "ctfs_competed": [],
                "aliases": [],
                "ratings": {
                    "crypto": 0, "forensics": 0, "misc": 0, "osint": 0,
                    "web": 0, "pwn-bin": 0, "reverse": 0, "htb": 0,
                    "cryptocurrency": 0, "network": 0, "overall": 0
                },
                "ranks": {
                    "crypto": 0, "forensics": 0, "misc": 0, "osint": 0,
                    "web": 0, "pwn-bin": 0, "reverse": 0, "htb": 0,
                    "cryptocurrency": 0, "network": 0, "overall": 0
                }
            }
            if not member.bot:
                member_cnt += 1
                members.update_one({"name": member.name}, {"$set": member_info}, upsert=True)
                print("[+] Added member {} to database of {}".format(member, guild.name))

        # Set team info in server info db
        team_info = {"name": str(guild.name), "guild id": str(guild.id),"num members": member_cnt}
        serverdb["team info"][str(guild.name)].update_one({"name": str(guild.name)}, {"$set": team_info}, upsert=True)

@bot.event # Displays error messages
async def on_command_error(ctx, error):
    if isinstance(error, commands.CommandNotFound):
        return
    if isinstance(error, commands.MissingRequiredArgument):
        await ctx.send("Missing a required argument.  Do >help")
    if isinstance(error, commands.MissingPermissions):
        await ctx.send("You do not have the appropriate permissions to run this command.")
    if isinstance(error, commands.BotMissingPermissions):
        await ctx.send("I don't have sufficient permissions!")
    else:
        await ctx.send("*error*")
        print("error not caught")
        print(error)

@bot.event # Adds new member to data structures
async def on_member_join(member):
    print(f'{member} has joined the server')
    for guild in bot.guilds:
        server = members[str(guild.id)]
        member_info = {"name": member.name, "points": 0, "ctfs_competed": []}
        if not member.bot:
            server.update_one({"name": member.name}, {"$set": member_info}, upsert=True)
            print("[+] Added member {} to database".format(member))

@bot.event # Removes existing member from data structures
async def on_member_remove(member):
    print(f'{member} has left the server')
    # Purge this member from the data structures

@bot.event
async def on_message(message):
    if str(message.guild.id) == '734854267847966720' or message.channel.name == 'ctf-bot-dev':
        await bot.process_commands(message)

################################ OTHER FUNCTIONS ###############################
@bot.command()
async def help(ctx, page=None):
    if page == 'ctftime':
        emb = discord.Embed(description=help_info.ctftime_help, colour=10181046)
        emb.set_author(name='CTFTime Help')
    elif page == 'ctf':
        emb = discord.Embed(description=help_info.ctf_help, colour=10181046)
        emb.set_author(name='CTF Help')
    elif page == 'leaderboard':
        emb = discord.Embed(description=help_info.leaderboard_help, colour=10181046)
        emb.set_author(name='Leaderboard Help')
    else:
        emb = discord.Embed(description=help_info.help_page, colour=10181046)
        emb.set_author(name='CTFBot Help')

    await ctx.channel.send(embed=emb)

@bot.command()
async def testPoints(ctx):
    message = "**Points:**\n```"
    for m in points:
        message += "{}: {}\n".format(m, points[m])
    await ctx.send(message + "```")

##################################### MAIN #####################################
# Loads cog extentions and starts up the bot
if __name__ == '__main__':
    for extension in extensions:
        bot.load_extension('cogs.' + extension)
    bot.run(discord_token)
