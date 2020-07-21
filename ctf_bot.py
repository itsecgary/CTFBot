import discord
import os
from discord.ext import commands, tasks
from itertools import cycle

################################ DATA STRUCTURES ###############################
bot = commands.Bot(command_prefix = '.')
status = cycle(['making challenges', 'getting mad... jk', 'calculating points'])
points = {}
num_ctfs = {}
ranking = []

################################ OTHER FUNCTIONS ###############################
@tasks.loop(seconds=60)
async def change_status():
    await bot.change_presence(activity=discord.Game(next(status)))


def sort_by_ranking():
    # Sort that shit
    print('Need Functionality Here')


##################################### COGS #####################################
@bot.command()
async def load(ctx, extension):
    bot.load_extension(f'cogs.{extension}')

@bot.command()
async def unload(ctx, extension):
    bot.unload_extension(f'cogs.{extension}')

for filename in os.listdir('./cogs'):
    if filename.endswith('.py'):
        bot.load_extension(f'cogs.{filename[:-3]}')


#################################### EVENTS ####################################
@bot.event
async def on_ready():
    print('Bot is booted up.')
    await bot.change_presence(status=discord.Status.idle)

    for guild in bot.guilds:
        for member in guild.members:
            points[member] = 0
            num_ctfs[member] = 0
            ranking.append(member)


@bot.event
async def on_member_join(member):
    print(f'{member} has joined the server')
    points[member] = 0
    num_ctfs[member] = 0
    ranking.append(member)

@bot.event
async def on_member_remove(member):
    print(f'{member} has left the server')

# Secret Token
bot.run('NzM0ODQxODkyMjkzODM2ODMx.XxYcrw.OIMDfr9DPu-BXfAF00WXIIXz57w')
