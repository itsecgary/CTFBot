import discord
import os
from discord.ext import commands

################################ DATA STRUCTURES ###############################
bot = commands.Bot(command_prefix = '.')
points = {}
num_ctfs = {}
ranking = []

##################################### COGS #####################################
@client.command()
async def load(ctx, extension):
    bot.load_extension(f'cogs.{extension}')

@client.command()
async def unload(ctx, extension):
    bot.unload_extension(f'cogs.{extension}')

for filename in os.listdir('./cogs'):
    if filename.endswith('.py'):
        bot.load_extension(f'cogs.{filename[:-3]}')

#################################### EVENTS ####################################
@bot.event
async def on_ready():
    print('Bot is ready.')

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
bot.run('')
