import discord
from discord.ext import commands

class Leaderboard(commands.Cog):

    def __init__(self, bot):
        self.bot = bot

    @commands.Cog.listener()
    async def ranking():
        print('Need Functionality Here')

    @commands.Cog.listener()
    async def leaderboard():
        print('Need Functionality Here')

    @commands.command()


def setup(bot):
    bot.add_cog(Leaderboard(bot))
