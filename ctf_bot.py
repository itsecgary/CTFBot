import discord
from discord.ext import commands, tasks
import os
from itertools import cycle
import tarfile
from datetime import date
from config_vars import *
import help_info

################################ DATA STRUCTURES ###############################
intents = discord.Intents.default()
intents.members = True
bot = commands.Bot(command_prefix = '!', intents=intents)
bot.remove_command('help')
extensions = ['rankings', 'ctftime', 'ctf']

#################################### EVENTS ####################################
@bot.event # Show banner and add members to respective guilds in db
async def on_ready():
    print("\n|--------------------|")
    print(f"|  {bot.user.name} - Online   |")
    print(f"|  discord.py {discord.__version__}  |")
    print("|--------------------|")
    await bot.change_presence(status=discord.Status.online, activity=discord.Game(name=">help"))

    # Create current member info
    for guild in bot.guilds:
        print("\n----------------------- {} -----------------------".format(guild.name))
        member_cnt = 0
        for member in guild.members:
            add_member(member, guild)
            if not member.bot: member_cnt += 1

        # Set team info in server info db
        server = client[str(guild.name).replace(' ', '-')]
        if not server['info'].find_one({'name': str(guild.name)}):
            team_info = {
                "name": str(guild.name),"guild id": str(guild.id),
                "num members": member_cnt, "competitions_overall": [],
                "competitions_semester": [], "competitions_year": [],
                "rankings_overall": {}, "rankings_semester": {}, "rankings_year": {}
            }
            server["info"].update_one({"name": str(guild.name)}, {"$set": team_info}, upsert=True)
        print("------------------------------------------------{}".format("-"*len(guild.name)))

@bot.event # Displays error messages
async def on_command_error(ctx, error):
    msg = ""
    if isinstance(error, commands.CommandNotFound):
        return
    if isinstance(error, commands.MissingRequiredArgument):
        msg += "Missing a required argument.  Do >help\n"
    if isinstance(error, commands.MissingPermissions):
        msg += "You do not have the appropriate permissions to run this command.\n"
    if isinstance(error, commands.BotMissingPermissions):
        msg += "I don't have sufficient permissions!\n"
    if msg == "":
        if not isinstance(error, commands.CheckFailure):
            msg += "Something went wrong.\n"
            print("error not caught")
            print(error)
            await ctx.send(msg)
    else:
        await ctx.send(msg)

@bot.event # Adds new member to data structures
async def on_member_join(member):
    print(f'{member} has joined the server')
    for guild in bot.guilds:
        if member in guild.members:
            cnt = add_member(member, guild)
            if cnt == 1:
                info = client[str(guild.name).replace(' ', '-')]['info']
                info2 = members.find_one({"name": str(guild.name).replace(' ', '-')})
                info2.update({"num members": info2["num members"] + 1})
            return

@bot.event # Removes existing member from data structures
async def on_member_remove(member):
    print(f'{member} has left the server')
    for guild in bot.guilds:
        if member in guild.members:
            members = client[str(guild.name).replace(' ', '-')]['members']
            members.remove({"name": str(member)})
            return

@bot.event
async def on_message(ctx):
    #if str(ctx.channel.type) == "private" or str(ctx.guild.id) == '734854267847966720' or ctx.channel.name == 'ctf-bot-dev':
    await bot.process_commands(ctx)

################################ OTHER FUNCTIONS ###############################
@bot.command()
async def help(ctx, page=None):
    if page == 'ctftime':
        emb = discord.Embed(description=help_info.ctftime_help, colour=10181046)
        emb.set_author(name='CTFTime Help')
    elif page == 'ctf':
        emb = discord.Embed(description=help_info.ctf_help, colour=10181046)
        emb.set_author(name='CTF Help')
    elif page == 'rank':
        emb = discord.Embed(description=help_info.leaderboard_help, colour=10181046)
        emb.set_author(name='Rank Help')
    else:
        emb = discord.Embed(description=help_info.help_page, colour=10181046)
        emb.set_author(name='CTFBot Help')
    await ctx.channel.send(embed=emb)

def add_member(member, guild):
    server = client[str(guild.name).replace(' ', '-')]
    members = server['members']
    rs = {'numerator': 0, 'denominator': 0, 'score': 0}
    struct = {"overall": 0, "crypto": rs, "forensics": rs,
              "reversing": rs, "osint": rs, "tryhackme": rs,
              "misc": rs, "web exploitation": rs, "pwn": rs}
    member_info = {
        "name": member.name + '#' + member.discriminator,
        "competed_overall": [],
        "competed_semester": [],
        "competed_year": [],
        "pfp": str(member.avatar_url),
        "ratings_overall": struct,
        "ratings_semester": struct,
        "ratings_year": struct
    }
    m = members.find_one({'name': member_info['name']})
    if not member.bot and m == None:
        members.update_one({"name": member.name}, {"$set": member_info}, upsert=True)
        print("[+] Added member {} to database of {}".format(member, guild.name))
    else:
        if member.bot:
            print("[/] Member {} not added - bot".format(member.name))
        else:
            print("[/] Member {} not added - already exists".format(member.name))

##################################### MAIN #####################################
if __name__ == '__main__': # Loads cog extentions and starts up the bot
    print("\n|-----------------------|\n| Loaded Cogs:          |")
    for extension in extensions:
        bot.load_extension('cogs.' + extension)
        print("|   - {}   {}|".format(extension.upper(), " "*(15-len(extension))))
    print("|-----------------------|\n")
    bot.run(discord_token)
