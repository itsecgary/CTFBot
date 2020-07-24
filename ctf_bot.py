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
        for member in guild.members:
            server = members[str(guild)]
            member_info = {"name": member.name, "points": 0, "ctfs_competed": []}
            if not member.bot:
                server.update_one({"name": member.name}, {"$set": member_info}, upsert=True)
                print("[+] Added member {} to database".format(member))

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
        print("error not caught")
        print(error)

@bot.event # Adds new member to data structures
async def on_member_join(member):
    print(f'{member} has joined the server')
    server = members[str(guild.id)]
    member_info = {"name": member.name, "points": 0, "ctfs_competed": []}
    if not member.bot:
        server.update_one({"name": member.name}, {"$set": member_info}, upsert=True)
        print("[+] Added member {} to database".format(member))

@bot.event # Removes existing member from data structures
async def on_member_remove(member):
    print(f'{member} has left the server')
    # Purge this member from the data structures

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


# Loads cog extentions and starts up the bot
if __name__ == '__main__':
    for extension in extensions:
        bot.load_extension('cogs.' + extension)
    bot.run(discord_token)
