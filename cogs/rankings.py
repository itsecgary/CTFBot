import discord
from discord.ext import commands, tasks

class Leaderboard(commands.Cog):

    def __init__(self, bot):
        self.bot = bot

    @commands.Cog.listener()
    async def on_ready(self):
        print('*** Leaderboard Cog Loaded ***')

    @commands.command()
    async def rank(self, ctx):
        print('Need Functionality Here')

    @commands.command()
    async def leaders(self, ctx):
        #message = "Points: {}".format(points)
        await ctx.send("HI")

def setup(bot):
    bot.add_cog(Leaderboard(bot))
