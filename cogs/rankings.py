import discord
from discord.ext import commands, tasks
import string
import json
import requests
import sys
import help_info
import traceback
sys.path.append("..")
from config_vars import *

################################ DATA STRUCTURES ###############################
points = {}
num_ctfs = {}
ranking = []

#################################### CLASSES ###################################
class Leaderboard(commands.Cog):

    def __init__(self, bot):
        self.bot = bot

    @commands.group()
    async def rank(self, ctx):
        if ctx.invoked_subcommand is None:
            await ctx.channel.send("Invalid command. Run `>help rank` for information on **rank** commands.")

    @rank.command()
    async def me(self, ctx):
        name = ctx.message.author
        server = client[str(ctx.guild.name).replace(' ', '-')]
        member = server['members'].find_one({'name': str(name)})

        count = 1
        for r in server['info'].find_one({'name': str(ctx.guild.name)})['ranking']:
            if r['name'] == str(name):
                break
            count += 1

        # Format info
        message = "**# of competitions:** {}\n\n".format(len(member['ctfs_competed']))
        message += "**Overall**: {} - *({})*\n".format(round(member['overall'],3), count)
        for cat, val in member['ratings'].items():
            message += "**{}**: {} *({})*\n".format(cat, round(val, 3), " ")

        # Send it
        emb = discord.Embed(description=message, colour=1752220)
        emb.set_author(name="{}'s CTF Profile'\n".format(str(name).split('#')[0]))
        await ctx.channel.send(embed=emb)

    @rank.command()
    async def top5(self, ctx, cat=None):
        server = client[str(ctx.guild.name).replace(' ', '-')]
        info = server['info'].find_one({'name': str(ctx.guild.name)})
        if not cat is None:
            await ctx.send("Not supported yet")
            return

        count = 0
        message = "**Top 5 Overall Scores** - {}\n".format(ctx.guild.name)
        for member in info['ranking']:
            if count < 5:
                message += "{}. {}: {}\n".format(count + 1, member['name'], member['score'])
            else:
                break
            count += 1

        if not message == "":
            await ctx.send(message)

#################################### SETUP #####################################
def setup(bot):
    bot.add_cog(Leaderboard(bot))
