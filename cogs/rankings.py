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
    "cryptocurrency": "https://cdn.dnaindia.com/sites/default/files/styles/full/public/2020/04/10/901440-cryptocurrency.jpg",
    "network": "https://www.pngkit.com/png/detail/365-3657626_wireshark-icon.png",
    "mobile": "https://dwkujuq9vpuly.cloudfront.net/news/wp-content/uploads/2020/03/Android-main.jpg",
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
        self.update_leaderboard.start()

    @tasks.loop(minutes=1440.0)
    async def update_leaderboard(self):
        for guild in self.bot.guilds:
            server = client[str(guild.name).replace(' ', '-')]
            lbs = server['leaderboards']
            info_db = server['info']
            year = int(datetime.date.today().year)
            month = int(datetime.date.today().month)
            day = int(datetime.date.today().day)
            print(f'Updating Leaderboards - {month}/{day}/{year}')

            # If after August 22, add leaderboard for upcoming school year
            if int(month) == 8 and int(day) > 22:
                name = f'{year}-{int(year)+1} School Year'
                lb = lbs.find_one({'name': name})
                if lb == None:
                    lb_info = {"name": name, "current": True, "rankings": info_db['rankings']}

                    # Finalize old leaderboard
                    name_OLD = f'{int(year)-1}-{year} School Year'
                    lb_info_OLD = {"name": name_OLD, "current": False, "rankings": info_db['rankings']}
                    lbs.update({'name': name_OLD}, {"$set": lb_info_OLD}, upsert=True)

                    # Clear rankings under info
                    server_info = {'ranking': {}, 'competitions': [], 'num competitions': 0}
                    info_db.update({'name': server_name}, {"$set": server_info}, upsert=True)
                else: # update leaderboards if already exists
                    lb['ranking'] = server['info']['rankings']
                    lb_info = lb

            # Else If leaderboard from previous year doesn't exist, make it!
            elif (int(month) < 8) or (int(month) == 8 and int(day) <= 22):
                name = f'{int(year)-1}-{year} School Year'
                lb = server['leaderboards'].find_one({'name': name})

                # If current school year leaderboard isn't up, make it
                # Else update it
                if lb == None:
                    lb_info = {"name": name, "current": True, "rankings": server['info']['rankings']}
                else:
                    lb['ranking'] = server['info']['rankings']
                    lb_info = lb

            lbs.update({'name': name}, {"$set": lb_info}, upsert=True)

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

        if (server['info'].find_one({'name': str(ctx.guild.name)})['ranking'] == {}):
            count = 0
        else:
            count = 1
            for r in server['info'].find_one({'name': str(ctx.guild.name)})['ranking']['overall']:
                if r['name'] == str(name):
                    break
                count += 1

        # Format info
        ti = "{}'s CTF Profile".format(str(name).split('#')[0])
        des = "**Overall:** {} ({})".format(round(member['overall'],3), place(count))
        emb = discord.Embed(title=ti, description=des, colour=1752220)
        for cat, val in member['ratings'].items():
            if cat == "crypto":
                cat = cat.capitalize() + " :abacus:"
            elif cat == "forensics":
                cat = cat.capitalize() + " :detective:"
            elif cat == "misc":
                cat = cat.capitalize() + " :joystick:"
            elif cat == "osint":
                cat = cat.upper() + " :mag_right:"
            elif cat == "web exploitation":
                cat = cat.split(' ')
                cat = "{} {} :spider_web:".format(cat[0].capitalize(), cat[1].capitalize())
            elif cat == "binary exploitation":
                cat = cat.split(' ')
                cat = "{} {} :game_die:".format(cat[0].capitalize(), cat[1].capitalize())
            elif cat == "reversing":
                cat = cat.capitalize() + " :slot_machine:"
            elif cat == "tryhackme":
                cat = "TryHackMe :computer:"
            elif cat == "cryptocurrency":
                cat = cat.capitalize() + " :moneybag:"
            elif cat == "network":
                cat = cat.capitalize() + " :satellite:"
            else:
                cat = cat.capitalize() + " :selfie:"
            emb.add_field(name=cat, value=round(val, 3), inline=True)

        # Send it
        emb.set_thumbnail(url=(ctx.message.author.avatar_url))
        #emb.set_author(name=)
        emb.set_footer(text="Number of competitions: {}\n\n".format(len(member['ctfs_competed'])))
        await ctx.channel.send(embed=emb)

    @rank.command()
    @in_channel()
    async def top5(self, ctx, cat=None, cat2=None):
        server = client[str(ctx.guild.name).replace(' ', '-')]
        info = server['info'].find_one({'name': str(ctx.guild.name)})

        if (info['ranking'] == {}):
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
        for member in info['ranking'][cat.lower()]:
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
