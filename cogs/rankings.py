import discord
from discord.ext import commands, tasks
import string
import json
import requests
import sys
import help_info
import datetime
import traceback
sys.path.append("..")
from config_vars import *

################################ DATA STRUCTURES ###############################
thumbnails = {
    "crypto": "https://mk0privacycanadehyf0.kinstacdn.com/wp-content/uploads/2020/01/Roth-13-Cipher.png",
    "forensics": "https://pbs.twimg.com/profile_images/1179025354129838080/NNXMmbyy_400x400.png",
    "misc": "https://fossbytes.com/wp-content/uploads/2017/01/pietscript-300x300.gif",
    "osint": "https://zdnet4.cbsistatic.com/hub/i/r/2014/09/18/a5431d0d-3f37-11e4-b6a0-d4ae52e95e57/resize/1200x900/c12b17da8fc4acbd7d687b0d943f1c41/anonymous-promises-payback-for-trademarked-anonymous-logo.jpg",
    "web exploitation": "https://invizon.com/wp-content/uploads/2013/09/webapp.jpg",
    "binary exploitation": "https://pbs.twimg.com/profile_images/1103593041766637568/aMkvIaLy.png",
    "reversing": "https://i.pinimg.com/originals/36/0e/24/360e24a8f599ea38bd1f1875d4890632.jpg",
    "tryhackme": "https://pbs.twimg.com/profile_images/1192912844297297920/73n4_SvJ_400x400.jpg",
    "overall": "https://www.cbtnuggets.com/blog/wp-content/uploads/2019/10/10684-1024x575.jpg"
}

def in_channel():
    async def tocheck(ctx):
        # A check for ctf context specific commands
        if not str(ctx.channel.type) == "private":
            return True
        else:
            await ctx.send("This command is not available over DM!")
            return False

    return commands.check(tocheck)

def place(pl):
    if pl == 0:
        pl = "N/A"
    elif pl >= 11 and pl <= 13:
        pl = "{}th".format(pl)
    elif pl % 10 == 1:
        pl = "{}st".format(pl)
    elif pl % 10 == 2:
        pl = "{}nd".format(pl)
    elif pl % 10 == 3:
        pl = "{}rd".format(pl)
    else:
        pl = "{}th".format(pl)
    return pl

#################################### CLASSES ###################################
class Leaderboard(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
        self.archive_leaderboard.start()

    @tasks.loop(minutes=1440.0)
    async def archive_leaderboard(self):
        for guild in self.bot.guilds:
            server_name = str(guild.name).replace(' ', '-')
            server = client[server_name]
            lbs = server['archived_leaderboards']
            info_db = server['info'].find_one({'name': str(guild.name)})
            year = int(datetime.date.today().year)
            month = int(datetime.date.today().month)
            day = int(datetime.date.today().day)
            print(f'Updating Leaderboards - {month}/{day}/{year}')

            name = ""
            name2 = ""
            cleared = {}
            if int(month) == 8 and int(day) == 24:
                name = f'Summer-{year}'
                lb_info = {"name": name, "rankings": info_db['rankings_semester']}
                cleared = {"competitons_semester": [], "rankings_semester": {},
                           "competitons_year": [], "rankings_year": {}}
            elif int(month) == 12 and int(day) == 24:
                name = f'Fall-{year}'
                lb_info = {"name": name, "rankings": info_db['rankings_semester']}
                cleared = {"competitons_semester": [],"rankings_semester": {}}
            elif int(month) == 1 and int(day) == 31:
                name = f'Winter-{year-1}-{year}'
                lb_info = {"name": name, "rankings": info_db['rankings_semester']}
                cleared = {"competitons_semester": [], "rankings_semester": {}}
            elif int(month) == 5 and int(day) == 24:
                name = f'Spring-{year}'
                name2 = f'Year-{year-1}-{year}'
                lb_info = {"name": name, "rankings": info_db['rankings_semester']}
                lb_info2 = {"name": name2, "rankings": info_db['rankings_year']}
                cleared = {"competitions_semester": [], "rankings_semester": {},
                           "competitions_year": [], "rankings_year": {}}
            else:
                name = "All-Time"
                lb_info = {"name": name, "rankings": info_db['rankings_overall']}

            if len(name) > 0:
                lbs.update_one({'name': name}, {"$set": lb_info}, upsert=True)
            if len(name2) > 0:
                lbs.update_one({'name': name2}, {"$set": lb_info2}, upsert=True)
            if len(cleared.keys()) > 0:
                server['info'].update({'name': str(guild.name)}, {"$set": cleared}, upsert=True)

    @commands.group()
    async def rank(self, ctx):
        if ctx.invoked_subcommand is None:
            await ctx.channel.send("Invalid command. Run `>help rank` for information on **rank** commands.")

    @rank.command()
    @in_channel()
    async def me(self, ctx):
        name = ctx.message.author
        server = client[str(ctx.guild.name).replace(' ', '-')]
        member = server['members'].find_one({'name': str(name)})

        if (server['info'].find_one({'name': str(ctx.guild.name)})['rankings_semester'] == {}):
            count = 0
        else:
            count = 1
            for r in server['info'].find_one({'name': str(ctx.guild.name)})['rankings_semester']['overall']:
                if r['name'] == str(name):
                    break
                count += 1

        # Format info
        ti = "{}'s CTF Profile".format(str(name).split('#')[0])
        des = "**Overall:** {} ({})".format(round(member['ratings_semester']['overall'],3), place(count))
        emb = discord.Embed(title=ti, description=des, colour=1752220)
        for cat, val in member['ratings_semester'].items():
            if cat == 'overall':
                continue
            if cat == "crypto":
                cat = cat.capitalize() + " :abacus:"
            elif cat == "forensics":
                cat = cat.capitalize() + " :detective:"
            elif cat == "misc":
                cat = cat.capitalize() + " :joystick:"
            elif cat == "osint":
                cat = cat.upper() + " :mag_right:"
            elif cat == "web exploitation":
                cat = "Web :spider_web:"
            elif cat == "pwn":
                cat = cat.split(' ')
                cat = "{} :game_die:".format(cat[0].capitalize())
            elif cat == "reversing":
                cat = cat.capitalize() + " :slot_machine:"
            elif cat == "tryhackme":
                cat = "TryHackMe :computer:"
            else:
                cat = cat.capitalize() + " :selfie:"
            emb.add_field(name=cat, value=round(val['score'], 3), inline=True)

        # Send it
        emb.set_thumbnail(url=(ctx.message.author.avatar_url))
        #emb.set_author(name=)
        emb.set_footer(text="Number of competitions: {}\n\n".format(len(member['competed_semester'])))
        await ctx.channel.send(embed=emb)

    @rank.command()
    @in_channel()
    async def top5(self, ctx, cat=None, cat2=None):
        server = client[str(ctx.guild.name).replace(' ', '-')]
        info = server['info'].find_one({'name': str(ctx.guild.name)})

        if (info['rankings_semester'] == {}):
            await ctx.send("No one on the server has competed in a competition yet!")
            return

        if cat is None:
            cat = "Overall"
        elif not cat2 is None:
            cat = cat.capitalize() + ' ' + cat2.capitalize()
        else:
            cat = cat.capitalize()

        if cat.lower() not in thumbnails.keys():
            await ctx.send("The CTF category is invalid.")
            return

        ti = "Top 5 {} Scores".format(cat, ctx.guild.name)
        emb = discord.Embed(title=ti, colour=11027200)
        emb.set_thumbnail(url=thumbnails[cat.lower()])

        count = 0
        for member in info['rankings_semester'][cat.lower()]:
            if count < 5:
                message = "({}) {}".format(place(count + 1), member['name'].split("#")[0])
                val = "{}".format(round(member['score'], 3))
                emb.add_field(name=message, value=val, inline=True)
            else:
                break
            count += 1

        await ctx.channel.send(embed=emb)

#################################### SETUP #####################################
def setup(bot):
    bot.add_cog(Leaderboard(bot))
