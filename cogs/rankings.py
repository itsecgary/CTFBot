import discord
from discord.ext import commands, tasks
import string
import json
import requests
import sys
import traceback
sys.path.append("..")
from config_vars import *

################################ DATA STRUCTURES ###############################
points = {}
num_ctfs = {}
ranking = []

#################################### METHODS ###################################
class Leaderboard(commands.Cog):

    def __init__(self, bot):
        self.bot = bot

    @commands.group()
    async def leaderboard(self, ctx):
        if ctx.invoked_subcommand is None:
            l_commands = list(set([c.qualified_name for c in CTF.walk_commands(self)][1:]))
            await ctx.send("Current ctf commands are: \n```\n{0}```".format('\n'.join(l_commands)))

    @commands.command()
    async def rank(self, ctx):
        print('Need Functionality Here')

    @commands.command()
    async def top10(self, ctx):
        print('Need Functionality Here')
        #message = "Points: {}".format(points)
        #await ctx.send("HI")

def setup(bot):
    bot.add_cog(Leaderboard(bot))
