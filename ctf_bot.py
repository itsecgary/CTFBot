import discord
from discord.ext import commands

client = commands.Bot(command_prefix = '.')

@client.event
async def on_ready():
    print('Bot is ready.')

client.run('NzM0ODQxODkyMjkzODM2ODMx.XxXk9Q.qtV_C7ziK3B3yQ1rOnprJZOndHA')
