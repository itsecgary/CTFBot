import discord
from discord.ext import tasks, commands
import string
import json
import requests
import sys
import re
import os
import traceback
import help_info
import time as tm
from dateutil.parser import parse
from datetime import *
from config_vars import *
sys.path.append("..")

################################ DATA STRUCTURES ###############################
chall_aliases = {
    "crypto": ["crypto", "cryptography", "aes", "rsa", "encryption", "encoding", "cipher", "ciphers"],
    "forensics": ["forensics", "stego", "steganography", "memory analysis"],
    "misc": ["misc", "other", "miscellaneous", "trivia", "random", "warmup"],
    "osint": ["osint" "open source intelligence"],
    "web exploitation": ["web", "web-exploitation", "web exploitation"],
    "binary exploitation": ["pwn", "pwning", "binary exploitation", "binary-exploitation", "exploitation", "kernel exploitation"],
    "reversing": ["reverse", "reversing", "re", "reverse engineering", "reverse-engineering"],
    "tryhackme": ["htb", "hackthebox", "hack the box", "try hack me", "tryhackme"],
    "cryptocurrency": ["cryptocurrency", "etherium", "coin", "bitcoin", "blockchain", "secure contracts"],
    "network": ["network", "networking", "network analysis", "wireshark", "rf", "pcap"],
    "mobile": ["mobile", "android", "mobile security", "apk"]
}

#################################### METHODS ###################################
def in_ctf_channel():
    async def tocheck(ctx):
        # A check for ctf context specific commands
        if not (str(ctx.channel.type) == "private") and \
           client[str(ctx.guild.name).replace(' ', '-')]['ctfs'].find_one({'name': str(ctx.message.channel)}):
            return True
        else:
            await ctx.send("You must be in a created ctf channel to use ctf commands!")
            return False

    return commands.check(tocheck)

def in_channel():
    async def tocheck(ctx):
        # A check for ctf context specific commands
        if not str(ctx.channel.type) == "private":
            return True
        else:
            await ctx.send("This command is not available over DM!")
            return False

    return commands.check(tocheck)

def check_aliases(guild, creds, channel_name):
    fingerprints = ["Powered by CTFd", "meta name=\"rctf-config\"", "CTFx"]
    server = client[str(guild.name).replace(' ', '-')]['ctfs']
    ctf = server.find_one({'name': channel_name})

    url = creds[str(guild.name).replace(' ', '-') + "." + channel_name]["site"]
    if url[-1] == "/": url = url[:-1]
    s = requests.session()
    r = s.get("{}/login".format(url))
    if fingerprints[0] in r.text:
        user = creds[str(guild.name).replace(' ', '-') + "." + channel_name]["user"]
        password = creds[str(guild.name).replace(' ', '-') + "." + channel_name]["pass"]
        try:
            nonce = r.text.split("csrfNonce': \"")[1].split('"')[0]
        except: # sometimes errors happen here - possibly due to CTFd versioning
            try:
                nonce = r.text.split("name=\"nonce\" value=\"")[1].split('">')[0]
            except:
                raise NonceNotFound("Was not able to find the nonce token from login. Could not check if aliases are correct.")

        # Login and check if credentials are valid
        r = s.post(f"{url}/login", data={"name": user, "password": password, "nonce": nonce})
        if "Your username or password is incorrect" in r.text:
            raise InvalidCredentials("Invalid login credentials. Could not check if aliases are correct.")

        # Get aliases for all members
        aliases = []
        members = s.get(f"{url}/api/v1/teams/me").json()['data']['members']
        for m_id in members:
            alias = s.get("{}/api/v1/users/{}".format(url, m_id)).json()
            aliases.append(alias['data']['name'])

        # iterate members in competition and check if they are in aliases
        members_not = []
        for name, attr in ctf['members'].items():
            if not attr['alias'] in aliases:
                members_not.append(name)

        if len(members_not) > 0:
            m = ""
            for mem in members_not:
                it = mem.split("#")
                user = discord.utils.get(guild.members, name = it[0], discriminator = it[1])
                m += user.mention + " "
            m += "\nYou have invalid aliases! "
            m += "Send `>ctf join [alias]` to update your alias or this will not count for your scoring."
            raise InvalidCredentials(m)

    else:
        raise InvalidCredentials("CTF is not based on CTFd - could not check if aliases are correct.")

def calculate(server_name, ctf_name):
    # Fetch Databases
    server = client[server_name.replace(' ', '-')]
    info_db = server['info']
    members = server['members']
    ctf = server['ctfs'].find_one({'name': ctf_name})
    num_members = len(ctf['members'].keys())

    # Calculate scores for each member of competition
    for name, mem_points in ctf['members'].items():
        # Add CTF to competed CTFs
        member = members.find_one({'name': name})
        arr = member['ctfs_competed']
        if arr == []:
            arr = [ctf_name]
        else:
            arr.append(ctf_name)
        length = len(arr)

        # Calculate each category
        for cat, val in mem_points.items():
            if not (cat == "alias") and not (ctf['points'][cat] == 0):
                solved_p = val
                total_p = ctf['points'][cat]
                curr_score = member['ratings'][cat] * (length-1)
                if total_p == 0:
                    score = 0
                else:
                    if num_members > 9:
                        num_members = 9
                    score = 10*(solved_p/total_p)*(1 + ctf['weight']/100)*(1 + (9 - num_members)/10)

                score = ((score + curr_score)/length)
                if score == 0:
                    score = int(score)
                else:
                    score = score + ((length)/50)
                member['ratings'][cat] = score

        # Calculate overall
        overall = 0
        for cat, val in member['ratings'].items():
            overall += val
        overall = overall/len(member['ratings'].values())

        # Update member's DB and set boolean to True
        server['members'].update({'name': name}, {"$set": {'overall': overall, 'ratings': member['ratings'], 'ctfs_competed': arr}}, upsert=True)
        server['ctfs'].update({'name': ctf_name}, {"$set": {'calculated?': True}}, upsert=True)

    # add overall to rankings
    rankings = {}
    overall_r = []
    already_got = []
    while (len(overall_r) < members.count()):
        highest = -1
        p = None
        for person in members.find():
            if person['overall'] > highest and not person['name'] in already_got:
                highest = person['overall']
                p = person
        already_got.append(p['name'])
        overall_r.append({'name': p['name'], 'score': p['overall']})
    rankings['overall'] = overall_r

    # add each CTF category to rankings
    for cat in chall_aliases.keys():
        arr = []
        already_got = []
        while (len(arr) < members.count()):
            highest = -1
            p = None
            for person in members.find():
                if person['ratings'][cat] > highest and not person['name'] in already_got:
                    highest = person['ratings'][cat]
                    p = person
            already_got.append(p['name'])
            arr.append({'name': p['name'], 'score': p['ratings'][cat]})
        rankings[cat] = arr

    # Update Guild Information
    comp_arr = info_db.find_one({'name': server_name})['competitions']
    if comp_arr == []:
        comp_arr = [ctf_name]
    else:
        comp_arr.append(ctf_name)

    # Update DB with all calculated information
    info_db.update({'name': server_name}, {"$set": {'ranking': rankings, 'competitions': comp_arr, 'num competitions': len(comp_arr)}}, upsert=True)

def get_one_CTFd(ctx, url, username, password, s, chall):
    r = s.get(f"{url}/login")
    try:
        nonce = r.text.split("csrfNonce': \"")[1].split('"')[0]
    except: # sometimes errors happen here - possibly due to CTFd versioning
        try:
            nonce = r.text.split("name=\"nonce\" value=\"")[1].split('">')[0]
        except:
            raise NonceNotFound("Was not able to find the nonce token from login.")

    # Login and check if credentials are valid
    r = s.post(f"{url}/login", data={"name": username, "password": password, "nonce": nonce})
    if "Your username or password is incorrect" in r.text:
        raise InvalidCredentials("Invalid login credentials")

    # Get challenge ID
    all_challenges = s.get(f"{url}/api/v1/challenges").json()
    chall_id = -1
    for c_hash in all_challenges['data']:
        if c_hash['name'].lower() == chall.lower():
            chall_id = c_hash['id']
            break

    # If chall name was not found, return with error message
    if chall_id == -1:
        raise InvalidCredentials("Challenge not found")

    # Grab challenge file and attach in message
    challenge_info = s.get("{}/api/v1/challenges/{}".format(url, chall_id)).json()
    return challenge_info

def get_one_rCTF(ctx, url, token, s, chall):
    heads = {
        "Content-Type": "application/json",
        "Authorization": "Bearer null"
    }
    r = s.post(f"{url}/api/v1/auth/login", json={"teamToken": token}, headers=heads)
    if "Your token is incorrect" in r.text or "badToken" in r.text:
        raise InvalidCredentials("Invalid login credentials")

    r_json = r.json()
    bearer_token = r_json['data']['authToken']
    heads = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.105 Safari/537.36",
        "Referer": "{}/challs".format(url),
        "Authorization": "Bearer {}".format(bearer_token)
    }

    # Get challenge information
    r_chals = s.get(f"{url}/api/v1/challs", headers=heads)
    all_challs = r_chals.json()
    chall_dict = -1
    for c_hash in all_challs['data']:
        if c_hash['name'].lower() == chall.lower():
            chall_dict = c_hash
            break

    # If chall name was not found, return with error message
    if chall_dict == -1:
        raise InvalidCredentials("Challenge not found")

    # Grab challenge file and attach in message
    print(chall_dict)
    return chall_dict

def get_challenges_CTFd(ctx, url, username, password, s):
    r = s.get(f"{url}/login")
    try:
        nonce = r.text.split("csrfNonce': \"")[1].split('"')[0]
    except: # sometimes errors happen here - possibly due to CTFd versioning
        try:
            nonce = r.text.split("name=\"nonce\" value=\"")[1].split('">')[0]
        except:
            raise NonceNotFound("Was not able to find the nonce token from login.")

    # Login and check if credentials are valid
    r = s.post(f"{url}/login", data={"name": username, "password": password, "nonce": nonce})
    if "Your username or password is incorrect" in r.text:
        raise InvalidCredentials("Invalid login credentials")

    # Get information from API
    all_challenges = s.get(f"{url}/api/v1/challenges").json()
    team_info = s.get(f"{url}/api/v1/teams/me").json()
    team_solves = s.get(f"{url}/api/v1/teams/me/solves").json()
    if 'success' not in team_solves: # ctf is user based
        team_info = s.get(f"{url}/api/v1/users/me").json()
        team_solves = s.get(f"{url}/api/v1/users/me/solves").json()

    # Variables
    challenges = {}
    point_info = {
        "crypto": 0, "forensics": 0, "misc": 0, "osint": 0,
        "web exploitation": 0, "binary exploitation": 0, "reversing": 0, "tryhackme": 0,
        "cryptocurrency": 0, "network": 0, "mobile": 0, "total": 0
    }
    solved_points = 0
    server = client[str(ctx.guild.name).replace(' ', '-')]['ctfs']
    members = server.find_one({'name': str(ctx.message.channel.category)})['members']

    # Reset points to 0
    for k, v in members.items():
        for cat, _ in v.items():
            if not cat == "alias": members[k][cat] = 0

    # Add all challenges
    if all_challenges['success'] == True:
        for chall in all_challenges['data']:
            cat = chall['category']
            challname = chall['name']
            value = chall['value']
            point_info['total'] += value

            # Add points for category
            for real_chall_name, aliases in chall_aliases.items():
                if cat.lower() in aliases:
                    point_info[real_chall_name] += value
                    break

            chall_entry = {'name': challname, 'solved': False, 'solver': '', 'points': value}
            if cat in challenges.keys():
                challenges[cat].append(chall_entry)
            else:
                challenges[cat] = [chall_entry]
    else:
        raise Exception("Error making request")

    # Add team solves
    if team_solves['success'] == True:
        for solve in team_solves['data']:
            # Get challenge info
            cat = solve['challenge']['category']
            challname = solve['challenge']['name']
            solver = solve['user']
            value = solve['challenge']['value']
            solved_points += value

            # Get user info
            r_user = s.get(f"{url}/api/v1/users/{solver}")
            user_profile = r_user.json()
            solver = user_profile['data']['name']

            # Add points for member who solved it for specific category
            for name, attr in members.items():
                if attr["alias"] == solver:
                    for real_chall_name, aliases in chall_aliases.items():
                        if cat.lower() in aliases:
                            members[name][real_chall_name] += value
                            break

            # Change challenge_solved info if solved by team
            for i in range(len(challenges[cat])):
                if challname == challenges[cat][i]['name']:
                    challenges[cat][i]['solved'] = True
                    challenges[cat][i]['solver'] = solver

    # Add total points to db
    rank = ""
    if "place" in team_info['data'].keys() and team_info['data']['place']:
        rank += team_info['data']['place']
    ctf_info = {'points': point_info, 'solved points': solved_points,
                'rank': rank, 'members': members}
    #server.update({'name': str(ctx.message.channel)}, {"$unset": {'total points': ""}}, upsert=True)
    server.update({'name': str(ctx.message.channel.category)}, {"$set": ctf_info}, upsert=True)
    return challenges

def get_challenges_rCTF(ctx, url, token, s):
    heads = {
        "Content-Type": "application/json",
        "Authorization": "Bearer null"
    }
    r = s.post(f"{url}/api/v1/auth/login", json={"teamToken": token}, headers=heads)
    if "Your token is incorrect" in r.text or "badToken" in r.text:
        raise InvalidCredentials("Invalid login credentials")

    r_json = r.json()
    bearer_token = r_json['data']['authToken']

    heads = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.105 Safari/537.36",
        "Referer": "{}/challs".format(url),
        "Authorization": "Bearer {}".format(bearer_token)
    }

    # Get challenge information
    r_chals = s.get(f"{url}/api/v1/challs", headers=heads)
    all_challs = r_chals.json()

    # Get team solves
    r_solves = s.get(f"{url}/api/v1/users/me", headers=heads)
    team_solves = r_solves.json()

    #print(all_challs)
    #print(team_solves)

    # Variables
    challenges = {}
    total_points = 0
    server = client[str(ctx.guild.name).replace(' ', '-')]['ctfs']

    print(all_challs['kind'])

    # Add all challenges
    if all_challs['kind'] == "goodChallenges":
        for chall in all_challs['data']:
            cat = chall['category']
            challname = chall['name']
            value = chall['points']
            total_points += value
            chall_entry = {'name': challname, 'solved': False, 'solver': '', 'points': value}
            if cat in challenges.keys():
                challenges[cat].append(chall_entry)
            else:
                challenges[cat] = [chall_entry]
    else:
        raise Exception("Error making request")

    # Add total points to db
    ctf_info = {'name': str(ctx.message.channel), 'total points': total_points}
    server.update({'name': str(ctx.message.channel)}, {"$unset": {'total points': ""}}, upsert=True)
    server.update({'name': str(ctx.message.channel)}, {"$set": ctf_info}, upsert=True)

    # Add team solves
    if team_solves['kind'] == "goodUserData":
        print("goodUserData")
        for solve in team_solves['data']['solves']:
            # Get challenge info
            cat = solve['category']
            challname = solve['name']

            # Change challenge solved info if solved by team
            for i in range(len(challenges[cat])):
                if challname == challenges[cat][i]['name']:
                    challenges[cat][i]['solved'] = True

    return challenges

#################################### CLASSES ###################################
class InvalidProvider(Exception):
    pass
class InvalidCredentials(Exception):
    pass
class NonceNotFound(Exception):
    pass

class CTF(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
        self.creds = {} # Stores credentials locally (not in database)
        self.current = [] # Stores started ctfs
        #self.get_info.start()

    #@tasks.loop(minutes=1.0)
    async def get_info(self):
        unix_now = int(datetime.utcnow().replace(tzinfo=timezone.utc).timestamp())

        # Get chall info for each running competition
        for guild in self.bot.guilds:
            server = client[str(guild.name).replace(' ', '-')]
            for ctf in server['ctfs'].find():
                # Pull challenges at very START and END of competition
                if ((unix_now - ctf['start'] < 122) and (unix_now - ctf['start'] > 0)) or \
                ((ctf['end'] - unix_now > 0) and (ctf['end'] - unix_now < 122)):
                    # Add name to current array
                    if not ctf['name'] in self.current:
                        self.current.append(ctf['name'])

                    # Check aliases
                    if str(guild.name).replace(' ', '-') + "." + str(ctf['name']) in self.creds:
                        c_id = 0
                        for channel in guild.channels:
                            if channel.name == ctf['name']:
                                print(channel.id)
                                c_id = channel.id
                                break
                        ch = self.bot.get_channel(c_id)
                        try:
                            check_aliases(guild, self.creds, str(ctf['name'])) # Check if all aliases are good!
                            await ch.send("Yep, everyone has correct aliases")
                        except InvalidCredentials as icm:
                            await ch.send(icm)

                # Right after competition ends
                elif unix_now - ctf['end'] < 122:
                    self.current.remove(ctf['name'])
                    c_id = 0

                    # Get channel id to send info
                    c_id = 0
                    for channel in guild.channels:
                        if channel.name == ctf['name']:
                            c_id = channel.id
                            break
                    ch = self.bot.get_channel(c_id)

                    # Display Statistics from competition
                    # Add simple team stats
                    ti = "Stats from {}".format(ctf['name'])
                    des = "**Members:** "
                    for name, v in ctf['members'].items():
                        des += "{}, ".format(name.split("#")[0])
                    des = des[:-2]
                    val = "{} out of {} points".format(ctf['solved points'], ctf['points']['total'])
                    rank = ctf['rank']
                    if rank == "": rank = "???"
                    emb = discord.Embed(title=ti, description=des, colour=10181046)
                    emb.add_field(name="Score", value=val, inline=True)
                    emb.add_field(name="Place", value=rank, inline=True)
                    emb.set_thumbnail(url=str(ctf['logo']))
                    await ch.send(embed=emb)

                    # Add all members stats
                    for name, attr in ctf['members'].items():
                        total = 0
                        ti = "{}'s Details".format(name.split('#')[0])
                        emb = discord.Embed(title=ti, description="[scored] / [total]", colour=10181046)
                        for cat, val in attr.items():
                            if not cat == "alias" and not val == 0:
                                nm = ' '.join([c.capitalize() for c in cat.split(' ')])
                                val2 = f"{val}" + " / {}".format(ctf['points'][cat])
                                emb.add_field(name=nm, value=val2, inline=False)
                                total += val

                        emb.set_thumbnail(url=(server['members'].find_one({'name': name})['pfp']))
                        emb.add_field(name="Total Points", value=total, inline=True)
                        await ch.send(embed=emb)
                        print("got user embed - {}".format(name))

                    # Calculate scores
                    calculate(str(guild.name), ctf)

    @commands.group()
    async def ctf(self, ctx):
        if ctx.invoked_subcommand is None:
            await ctx.channel.send("Invalid command. Run `>help ctf` for information on **ctf** commands.")

    @commands.bot_has_permissions(manage_channels=True, manage_roles=True)
    @commands.has_permissions(manage_channels=True)
    @ctf.command()
    @in_channel()
    async def create(self, ctx, link):
        # If general competition not on ctftime
        if not ("https://ctftime.org" in str(link)):
            category = discord.utils.get(ctx.guild.categories, name="CTF")
            await ctx.guild.create_text_channel(name=str(link), category=category)
            await ctx.guild.create_role(name=str(link), mentionable=True)
            await ctx.message.add_reaction("✅")
            return

        # Parse CTFTime Link
        if link[-1] == "/": link = link[:-1]
        event_id = link.split("/")[-1]
        link = "https://ctftime.org/api/v1/events/{}/".format(event_id)
        head = {'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:61.0) Gecko/20100101 Firefox/61.0'}

        # Get and parse JSON data for competition
        r_event = requests.get(url=link, headers=head)

        # Error message when CTFTime is down and doesn't do anything
        if r_event.status_code == 404:
            await ctx.channel.send("CTFTime is currently down. Try again later!")
            return

        event_json = r_event.json()

        unix_now = int(datetime.utcnow().replace(tzinfo=timezone.utc).timestamp())
        (ctf_start, ctf_end) = (parse(event_json['start'].replace('T', ' ').split('+', 1)[0]), parse(event_json['finish'].replace('T', ' ').split('+', 1)[0]))
        (unix_start, unix_end) = (int(ctf_start.replace(tzinfo=timezone.utc).timestamp()), int(ctf_end.replace(tzinfo=timezone.utc).timestamp()))
        (ctf_hours, ctf_days) = (str(event_json["duration"]["hours"]), str(event_json["duration"]["days"]))
        ctf_info = {
            "name": event_json["title"].replace(' ', '-').lower(),
            "text_channel": event_json["title"].replace(' ', '-').lower(),
            "website": event_json["url"], "weight": event_json["weight"],
            "description": event_json["description"], "start": unix_start,
            "end": unix_end, "duration": (((ctf_days + " days, ") + ctf_hours) + " hours"),
            "members": {}, "calculated?": False, "logo": event_json["logo"],
            "teams": {}
        }

        # Update CTF DB for guild
        server = client[str(ctx.guild.name).replace(' ', '-')]['ctfs']
        server.update({'name': ctf_info["name"]}, {"$set": ctf_info}, upsert=True)

        # Discord server stuff
        ctf_name = ctf_info["name"]
        if ctf_name not in [c.name for c in ctx.guild.categories]:
            print(ctx.guild.categories)
            cat = await ctx.guild.create_category(ctf_name)
            length = len(ctx.guild.categories)
            await cat.edit(position=length-2)
            print(ctx.guild.categories)
        category = discord.utils.get(ctx.guild.categories, name=ctf_name)

        await ctx.guild.create_text_channel(name=ctf_name, category=category)
        await ctx.guild.create_role(name=ctf_name, mentionable=True)
        await ctx.message.add_reaction("✅")

    @commands.bot_has_permissions(manage_channels=True, manage_roles=True)
    @commands.has_permissions(manage_channels=True)
    @ctf.command()
    @in_channel()
    @in_ctf_channel()
    async def form(self, ctx, teamname):
        servcat = str(ctx.message.channel)
        teamname = teamname.replace(' ','-').lower()
        category = discord.utils.get(ctx.guild.categories, name=servcat)
        if category == None: # Checks if category exists, if it doesn't it will create it.
            cat = await ctx.guild.create_category(servcat)
            await cat.edit(position=2)
            category = discord.utils.get(ctx.guild.categories, name=servcat)

        server = client[str(ctx.guild.name).replace(' ', '-')]['ctfs']
        ctf_name = server.find_one({'name': str(ctx.message.channel)})

        # Checks to see if team has alreasdy been formed
        if teamname in ctf_name['teams']:
            await ctx.send("This team has already been formed! If you wish to make a separate team, please use a different team name.")
            return

        # Creates the team info for the database and for a role and channel
        team_info = {
            "name": teamname,
            "members": {},
            "creds": {}
        }

        # Update CTF DB for guild and for the team being made
        server = client[str(ctx.guild.name).replace(' ', '-')]['ctfs']
        ctf = server.find_one({'name': str(ctx.message.channel)})
        teams = ctf['teams']
        teams[teamname] = team_info

        server.update({'name': str(ctx.message.channel)}, {"$set": {'teams': teams}}, upsert=True)

        # create role
        await ctx.guild.create_role(name=teamname, mentionable=True)
        await ctx.guild.create_text_channel(name=teamname, category=category)
        await ctx.guild.create_voice_channel(name=teamname, category=category)

        roles = ctx.guild.roles
        channels = ctx.guild.channels
        voice_channels = ctx.guild.voice_channels
        for r in roles:
            if r.name == teamname:
                role = r
        for c in channels:
            if c.name == teamname:
                await c.set_permissions(ctx.guild.default_role, send_messages=False, read_messages=False)
                await c.set_permissions(role, read_messages=True, send_messages=True)
        for vc in voice_channels:
            if vc.name == teamname:
                await vc.set_permissions(ctx.guild.default_role, send_messages=False, read_messages=False)
                await vc.set_permissions(role, read_messages=True, send_messages=True)

        await ctx.message.add_reaction("✅")

    @commands.bot_has_permissions(manage_channels=True, manage_roles=True)
    @commands.has_permissions(manage_channels=True)
    @ctf.command()
    @in_channel()
    async def disband(self, ctx):
        teamname = str(ctx.message.channel)
        server = client[str(ctx.guild.name).replace(' ', '-')]['ctfs']
        ctf = server.find_one({'name': str(ctx.message.channel.category)})
        teams = ctf['teams']

        # Checks if team exists
        if teamname not in teams:
            await ctx.send("This is not a team channel")
            return

        del teams[teamname]
        server.update({'name': str(ctx.message.channel.category)}, {"$set": {'teams': teams}}, upsert=True)
        channel = discord.utils.get(ctx.guild.text_channels, name=str(ctx.message.channel.category).lower())
        ch = self.bot.get_channel(channel.id)
        #print(ctx.guild.channels)
        await ch.send(f"`{str(ctx.message.channel)}` disbanded")

        # remove role and channel
        try:
            role = discord.utils.get(ctx.guild.roles, name=teamname)
            await role.delete()
            await ch.send(f"`{role.name}` role deleted")
            print(teamname.lower())
            print(str(ctx.message.channel.category).lower())
            for vc in ctx.guild.voice_channels:
                if (vc.name.lower() == teamname.lower()) and (vc.category.lower() == str(ctx.message.channel.category).lower()):
                    await vc.delete()
                    break
            for c in ctx.guild.voice_channels:
                if (c.name.lower() == teamname.lower()) and (c.category.lower() == str(ctx.message.channel.category).lower()):
                    await c.delete()
                    break
        except: # role most likely already deleted with archive
            pass

    @commands.bot_has_permissions(manage_channels=True, manage_roles=True)
    @commands.has_permissions(manage_channels=True)
    @ctf.command()
    @in_channel()
    @in_ctf_channel()
    async def add(self, ctx, user: discord.User, alias, teamname):
        server = client[str(ctx.guild.name).replace(' ', '-')]['ctfs']
        ctf = server.find_one({'name': str(ctx.message.channel)})
        teamname = teamname.replace(' ','-').lower()

        # get member
        channel = discord.utils.get(ctx.guild.channels, name=teamname)
        member = ctx.guild.get_member(user.id)

        # get role & add role to user
        roles = ctx.guild.roles
        role = ""
        for r in roles:
            if r.name == teamname:
                await member.add_roles(r)

        # add member to team in DB
        teams = ctf['teams']
        member_info = { "name": str(user), "alias": alias, "solves": []}
        teams[teamname]['members'][str(user)] = member_info
        server.update({'name': str(ctx.message.channel)}, {"$set": {'teams': teams}}, upsert=True)

        await ctx.message.add_reaction("✅")
        await channel.send("{} has joined {}!".format(user, teamname))

    @ctf.command()
    @in_channel()
    async def members(self, ctx, teamname):
        server = client[str(ctx.guild.name).replace(' ', '-')]
        ctf = server['ctfs'].find_one({'name': str(ctx.message.channel)})
        teamname = teamname.replace(' ','-').lower()
        if ctf == None:
            ctf = server['ctfs'].find_one({'name': str(ctx.message.channel.category)})
            if ctf == None:
                await ctx.channel.send("Run this command under the specific competition category")
                return

        if teamname not in ctf['teams']:
            await ctx.channel.send("This team does not exist!")
            return

        # add member to team in DB
        member_list = ctf['teams'][teamname]['members']
        print(member_list)
        for m in member_list:
            member = server['members'].find_one({'name': m})
            ti = member_list[m]['alias']
            des = "Overall: {}".format(member['overall'])
            emb = discord.Embed(title=ti, description=des, colour=1752220)
            emb.add_field(name="Solves: ", value=member_list[m]['solves'], inline=True)
            emb.set_thumbnail(url=member['pfp'])
            await ctx.channel.send(embed=emb)

    @commands.bot_has_permissions(manage_channels=True, manage_roles=True)
    @commands.has_permissions(manage_channels=True)
    @ctf.command()
    @in_ctf_channel()
    async def delete(self, ctx):
        # Delete role from server, delete entry from db
        try:
            role = discord.utils.get(ctx.guild.roles, name=str(ctx.message.channel))
            await role.delete()
            await ctx.send(f"`{role.name}` role deleted")
        except: # role most likely already deleted with archive
            pass
        client[str(ctx.guild.name).replace(' ', '-')]['ctfs'].remove({'name': str(ctx.message.channel)})
        await ctx.send(f"`{str(ctx.message.channel)}` deleted from db")

    @commands.bot_has_permissions(manage_channels=True, manage_roles=True)
    @commands.has_permissions(manage_channels=True)
    @ctf.command()
    @in_ctf_channel()
    async def archive(self, ctx):
        ctfname = str(ctx.message.channel)
        role = discord.utils.get(ctx.guild.roles, name=str(ctx.message.channel))
        if role != None:
            await role.delete()
        await ctx.send(f"`{role.name}` role deleted, archiving channel.")
        servarchive = "ARCHIVE"
        category = discord.utils.get(ctx.guild.categories, name=servarchive)

        if category == None: # Checks if category exists, if it doesn't it will create it.
            await ctx.guild.create_category(name=servarchive)
            category = discord.utils.get(ctx.guild.categories, name=servarchive)
        await ctx.message.channel.edit(syncpermissions=True, category=category)

        # delete all channels in category
        for channel in ctx.guild.channels:
            if str(channel.category).lower() == ctfname.lower():
                await channel.delete()
        # delete all voice channels in category
        for vc in ctx.guild.voice_channels:
            if str(vc.category).lower() == ctfname.lower():
                await vc.delete()
        # delete category
        for cat in ctx.guild.categories:
            if str(cat.name).lower() == ctfname.lower():
                await cat.delete()

    @commands.bot_has_permissions(manage_roles=True)
    @ctf.command()
    @in_ctf_channel()
    async def join(self, ctx, alias):
        role = discord.utils.get(ctx.guild.roles, name=str(ctx.message.channel))
        user = ctx.message.author
        await user.add_roles(role)
        await ctx.send(f"{user} has joined the {str(ctx.message.channel)} team!")

        # Get DB
        server = client[str(ctx.guild.name).replace(' ', '-')]['ctfs']
        mems = client[str(ctx.guild.name).replace(' ', '-')]['members']
        ctf = server.find_one({'name': str(ctx.message.channel)})

        # Add member to CTF DB along with alias in order for point processing
        members = ctf['members']
        members[str(user)] = {
            "alias": alias, "crypto": 0, "forensics": 0, "misc": 0, "osint": 0, "web exploitation": 0,
            "binary exploitation": 0, "reversing": 0, "tryhackme": 0, "cryptocurrency": 0, "network": 0, "mobile": 0
        }
        server.update({'name': str(ctx.message.channel)}, {"$unset": {'members': ""}}, upsert=True)
        server.update({'name': str(ctx.message.channel)}, {"$set": {'members': members}}, upsert=True)

    @commands.bot_has_permissions(manage_roles=True)
    @ctf.command()
    @in_ctf_channel()
    async def leave(self, ctx):
        role = discord.utils.get(ctx.guild.roles, name=str(ctx.message.channel))
        user = ctx.message.author
        await user.remove_roles(role)
        await ctx.send(f"{user} has left the {str(ctx.message.channel)} team.")

    @ctf.command()
    @in_channel()
    async def setcreds(self, ctx, username, password, site):
        teamname = str(ctx.message.channel)
        server = client[str(ctx.guild.name).replace(' ', '-')]['ctfs']
        ctf = server.find_one({'name': str(ctx.message.channel.category)})
        teams = ctf['teams']

        # Checks if team exists
        if teamname not in teams:
            await ctx.send("This is not a team channel")
            return
        creds = teams[str(ctx.message.channel)]['creds']

        if site == None:
            site = password
            password = None

        replace_msg = ""
        if creds and len(creds.keys()) > 0:
            if password == None:
                name = creds['token']
                replace_msg += "Replacing credential token"
            else:
                name = creds['user']
                replace_msg += "Replacing **{}**'s creds".format(name)

        if password == None:
            creds = {"token": username, "site": site}
            message = "CTF credentials set. \n**Token:**\t ".format(username) + \
                  "` * * * * * * * * ` \n**Website:**\t` {} `".format(site)
        else:
            creds = {"user": username, "pass": password, "site": site}
            message = "CTF credentials set. \n**Username:**\t` {0} ` ".format(username) + \
                  "\n**Password:**\t` * * * * * * * * ` \n**Website:**\t` {} `".format(site)

        teams[str(ctx.message.channel)]['creds'] = creds
        server.update({'name': str(ctx.message.channel.category)}, {"$set": {'teams': teams}}, upsert=True)

        # Get rid of pins
        pinned = await ctx.channel.pins()
        for pin in pinned:
            if "CTF credentials set." in pin.content:
                await pin.unpin()

        # Send replace message if need be and send real message
        if not replace_msg == "":
            await ctx.channel.send(replace_msg)
        msg = await ctx.channel.send(message)
        await msg.pin()

    @staticmethod
    async def pull_challs(self, ctx, creds):
        fingerprints = ["Powered by CTFd", "meta name=\"rctf-config\"", "CTFx"]
        try:
            if not creds:
                await ctx.send("Set credentials with `>ctf setcreds ...`")
                return

            url = creds["site"]

            if url[-1] == "/": url = url[:-1]
            s = requests.session()
            r = s.get("{}/login".format(url))

            # Error message when CTF site is down and then returns
            if r.status_code == 404:
                await ctx.channel.send("CTF site is down. Try pulling challenges when it's up!")
                return

            if fingerprints[0] in r.text:
                user = creds["user"]
                password = creds["pass"]
                ctfd_challs = get_challenges_CTFd(ctx, url, user, password, s)
            elif fingerprints[1] in r.text:
                token = self.creds["token"]
                ctfd_challs = get_challenges_rCTF(ctx, url, token, s)
            elif fingerprints[2] in r.text:
                # TODO - Implement CTFx functionality
                raise InvalidProvider("CTFx functionality coming soon - cannot pull challenges.")
            else:
                raise InvalidProvider("CTF is not based on CTFd or rCTF - cannot pull challenges.")

            ctf_info = {'name': str(ctx.message.channel), 'challenges': ctfd_challs}
            server = client[str(ctx.guild.name).replace(' ', '-')]['ctfs']
            server.update({'name': str(ctx.message.channel)}, {"$set": ctf_info}, upsert=True)
            await ctx.message.add_reaction("✅")
            return
        except InvalidProvider as ipm:
            await ctx.send(ipm)
        except InvalidCredentials as icm:
            await ctx.send(icm)
        except NonceNotFound as nnfm:
            await ctx.send(nnfm)
        except requests.exceptions.MissingSchema:
            await ctx.send("Supply a valid url in the form: `http(s)://ctf.url`")
        except:
            traceback.print_exc()

    @ctf.command()
    @in_channel()
    async def challs(self, ctx):
        teamname = str(ctx.message.channel)
        ctf_challenge_list = []
        server = client[str(ctx.guild.name).replace(' ', '-')]['ctfs']
        ctf = server.find_one({'name': str(ctx.message.channel.category)})
        unix_now = int(datetime.utcnow().replace(tzinfo=timezone.utc).timestamp())
        teams = ctf['teams']

        #Checks if team exists
        if teamname not in teams:
            await ctx.send("This is not a team channel")
            return
        creds = teams[str(ctx.message.channel)]['creds']

        if not ctf:
            await ctx.send("Please create a separate channel for this CTF")
            return
        elif (ctf['start'] > unix_now):
            actual_date = datetime.fromtimestamp(ctf['start']).strftime('%H:%M ET on %m/%d/%Y')
            await ctx.send("CTF has not started! Wait until {}".format(actual_date))
            return
        elif (ctf['end'] < unix_now):
            await ctx.send("CTF is over, but I still might have chall info.")
            await CTF.pull_challs(self, ctx, creds)
            #if not ctf['calculated?']: # we only want to calculate once
                #calculate(str(ctx.guild.name), str(ctx.message.channel))
        else:
            await CTF.pull_challs(self, ctx, creds)


        # Print challenges to chat
        if 'challenges' in ctf.keys():
            ctf = server.find_one({'name': str(ctx.message.channel.category)}) # update local hash
            try:
                ctf_challenge_list = []
                message = ""
                message2 = ""
                print(ctf['challenges'].items())
                for k, v in ctf['challenges'].items():
                    if len(message) > 1500:
                        message2 = message
                        message = ""
                    message += "- {0}\n".format(k)
                    for chall in v:
                        message += "[{0}]({1}): ".format(chall['name'], chall['points'])
                        if chall['solved'] == True:
                            message += "Solved - {0}\n".format(chall['solver'])
                        else:
                            message += "Unsolved\n"
                    message += "\n"

                await ctx.send("```md\n{0}```".format(message))
                if message2:
                    await ctx.send("```md\n{0}```".format(message2))
            except:
                traceback.print_exc()

    @ctf.command()
    @in_ctf_channel()
    async def pull(self, ctx, chall):
        fingerprints = ["Powered by CTFd", "meta name=\"rctf-config\"", "CTFx"]
        url = self.creds[str(ctx.guild.name).replace(' ', '-') + "." + str(ctx.message.channel)]["site"]
        server = client[str(ctx.guild.name).replace(' ', '-')]['ctfs']
        ctf = server.find_one({'name': str(ctx.message.channel)})
        unix_now = int(datetime.utcnow().replace(tzinfo=timezone.utc).timestamp())

        if not ctf:
            await ctx.send("Please create a separate channel for this CTF")
            return
        elif (ctf['start'] > unix_now):
            await ctx.send("CTF has not started! Wait until {}".format(ctf['start']))
            return
        elif (ctf['end'] < unix_now):
            await ctx.send("CTF is over, but I still might have the challenge here somewhere...")

        # Get challenge info
        try:
            if not self.creds[str(ctx.guild.name).replace(' ', '-') + "." + str(ctx.message.channel)]:
                await ctx.send("Set credentials with `>ctf setcreds ...`")
                return

            if url[-1] == "/": url = url[:-1]
            s = requests.session()
            r = s.get("{}/login".format(url))
            if fingerprints[0] in r.text:
                user = self.creds[str(ctx.guild.name).replace(' ', '-') + "." + str(ctx.message.channel)]["user"]
                password = self.creds[str(ctx.guild.name).replace(' ', '-') + "." + str(ctx.message.channel)]["pass"]
                challenge_info = get_one_CTFd(ctx, url, user, password, s, chall)
                challenge_info = challenge_info['data']
                chall_value = challenge_info['value']
            elif fingerprints[1] in r.text:
                token = self.creds[str(ctx.guild.name).replace(' ', '-') + "." + str(ctx.message.channel)]["token"]
                challenge_info = get_one_rCTF(ctx, url, token, s, chall)
                chall_value = challenge_info['points']
            elif fingerprints[2] in r.text:
                raise InvalidProvider("CTFx functionality coming soon - cannot pull challenge.")
            else:
                raise InvalidProvider("CTF is not based on CTFd or rCTF - cannot pull challenge.")

            # Send info
            ti = "{} ({})".format(challenge_info['name'], chall_value)
            des = "{}".format(challenge_info['description'])
            emb = discord.Embed(title=ti, description=des, colour=1752220)
            emb.add_field(name="Category", value=challenge_info['category'], inline=True)
            emb.add_field(name="Solves", value=challenge_info['solves'], inline=True)

            # Send attachments a.nd reaction
            files = []
            m = ""
            for i in range(len(challenge_info['files'])):
                fn = challenge_info['files'][i].split('?')[0].split('/')[-1]
                u = "{}{}".format(url, challenge_info['files'][i])
                contents = s.get(u).text.encode()
                #contents = contents
                with open(fn, 'wb') as f:
                    f.write(contents)
                files.append(fn)
                m += fn + ', '

            if m == "": m = "N/A  "
            emb.add_field(name="Files", value=m[:-2], inline=True)
            await ctx.send(embed=emb)
            for j in files:
                await ctx.channel.send(file=discord.File(j))
                os.remove(j)
            await ctx.message.add_reaction("✅")
        except InvalidProvider as ipm:
            await ctx.send(ipm)
        except InvalidCredentials as icm:
            await ctx.send(icm)
        except NonceNotFound as nnfm:
            await ctx.send(nnfm)
        except requests.exceptions.MissingSchema:
            await ctx.send("Supply a valid url in the form: `http(s)://ctf.url`")
        except:
            traceback.print_exc()

    @ctf.command()
    @in_channel()
    async def solve(self, ctx, chall_name):
        teamname = str(ctx.message.channel)
        server = client[str(ctx.guild.name).replace(' ', '-')]['ctfs']
        ctf = server.find_one({'name': str(ctx.message.channel.category)})
        teams = ctf['teams']

        # If team doesn't exist, return message and quit
        if teamname not in teams:
            await ctx.send("You are only able to run this command in a team channel.")
            return

        #print(teams)
        #print(teams[teamname])
        teams[teamname]['members'][str(ctx.message.author)]['solves'].append(chall_name.replace(' ','-').lower())
        server.update({'name': str(ctx.message.channel.category)}, {"$set": {'teams': teams}}, upsert=True)
        await ctx.channel.send("{} has solved `{}`".format(ctx.author.name, chall_name))

#################################### SETUP #####################################
def setup(bot):
    bot.add_cog(CTF(bot))
