#!/usr/bin/env python3
#
# lint.py - part of the FDroid server tool
# Copyright (C) 2013-2014 Daniel Martí <mvdan@mvdan.cc>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See th
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public Licen
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import difflib
import platform
import re
import sys
import urllib.parse
from argparse import ArgumentParser
from pathlib import Path

from fdroidserver._yaml import yaml

from . import _, common, metadata, rewritemeta


def enforce_https(domain):
    return (
        re.compile(
            r'^http://([^/]*\.)?' + re.escape(domain) + r'(/.*)?', re.IGNORECASE
        ),
        domain + " URLs should always use https://",
    )


HTTPS_ENFORCINGS = [
    enforce_https('github.com'),
    enforce_https('gitlab.com'),
    enforce_https('bitbucket.org'),
    enforce_https('apache.org'),
    enforce_https('google.com'),
    enforce_https('git.code.sf.net'),
    enforce_https('svn.code.sf.net'),
    enforce_https('anongit.kde.org'),
    enforce_https('savannah.nongnu.org'),
    enforce_https('git.savannah.nongnu.org'),
    enforce_https('download.savannah.nongnu.org'),
    enforce_https('savannah.gnu.org'),
    enforce_https('git.savannah.gnu.org'),
    enforce_https('download.savannah.gnu.org'),
    enforce_https('github.io'),
    enforce_https('gitlab.io'),
    enforce_https('githubusercontent.com'),
]


def forbid_shortener(domain):
    return (
        re.compile(r'https?://([^.]*\.)?' + re.escape(domain) + r'/.*'),
        _("URL shorteners should not be used ({domain})").format(domain=domain),
    )


# Generated using:
# curl --silent https://raw.githubusercontent.com/PeterDaveHello/url-shorteners/refs/heads/master/list \
#    | grep '^\w' \
#    | sort -u \
#    | xargs printf "    forbid_shortener('%s'),\n" \
#    | wl-copy
HTTP_URL_SHORTENERS = [
    forbid_shortener('0.gp'),
    forbid_shortener('02faq.com'),
    forbid_shortener('0a.sk'),
    forbid_shortener('101.gg'),
    forbid_shortener('12ne.ws'),
    forbid_shortener('17mimei.club'),
    forbid_shortener('1drv.ms'),
    forbid_shortener('1ea.ir'),
    forbid_shortener('1kh.de'),
    forbid_shortener('1o2.ir'),
    forbid_shortener('1shop.io'),
    forbid_shortener('1un.fr'),
    forbid_shortener('1url.com'),
    forbid_shortener('1url.cz'),
    forbid_shortener('2.gp'),
    forbid_shortener('2.ht'),
    forbid_shortener('2.ly'),
    forbid_shortener('2doc.net'),
    forbid_shortener('2fear.com'),
    forbid_shortener('2kgam.es'),
    forbid_shortener('2link.cc'),
    forbid_shortener('2nu.gs'),
    forbid_shortener('2pl.us'),
    forbid_shortener('2u.lc'),
    forbid_shortener('2u.pw'),
    forbid_shortener('2wsb.tv'),
    forbid_shortener('3.cn'),
    forbid_shortener('3.ly'),
    forbid_shortener('301.link'),
    forbid_shortener('3le.ru'),
    forbid_shortener('4.gp'),
    forbid_shortener('4.ly'),
    forbid_shortener('49rs.co'),
    forbid_shortener('4sq.com'),
    forbid_shortener('5.gp'),
    forbid_shortener('53eig.ht'),
    forbid_shortener('5du.pl'),
    forbid_shortener('5w.fit'),
    forbid_shortener('6.gp'),
    forbid_shortener('6.ly'),
    forbid_shortener('69run.fun'),
    forbid_shortener('6g6.eu'),
    forbid_shortener('7.ly'),
    forbid_shortener('707.su'),
    forbid_shortener('71a.xyz'),
    forbid_shortener('7news.link'),
    forbid_shortener('7ny.tv'),
    forbid_shortener('7oi.de'),
    forbid_shortener('8.ly'),
    forbid_shortener('89q.sk'),
    forbid_shortener('92url.com'),
    forbid_shortener('985.so'),
    forbid_shortener('98pro.cc'),
    forbid_shortener('9mp.com'),
    forbid_shortener('9splay.store'),
    forbid_shortener('a.189.cn'),
    forbid_shortener('a.co'),
    forbid_shortener('a360.co'),
    forbid_shortener('aarp.info'),
    forbid_shortener('ab.co'),
    forbid_shortener('abc.li'),
    forbid_shortener('abc11.tv'),
    forbid_shortener('abc13.co'),
    forbid_shortener('abc7.la'),
    forbid_shortener('abc7.ws'),
    forbid_shortener('abc7ne.ws'),
    forbid_shortener('abcn.ws'),
    forbid_shortener('abe.ma'),
    forbid_shortener('abelinc.me'),
    forbid_shortener('abnb.me'),
    forbid_shortener('abr.ai'),
    forbid_shortener('abre.ai'),
    forbid_shortener('accntu.re'),
    forbid_shortener('accu.ps'),
    forbid_shortener('acer.co'),
    forbid_shortener('acer.link'),
    forbid_shortener('aces.mp'),
    forbid_shortener('acortar.link'),
    forbid_shortener('act.gp'),
    forbid_shortener('acus.org'),
    forbid_shortener('adaymag.co'),
    forbid_shortener('adbl.co'),
    forbid_shortener('adf.ly'),
    forbid_shortener('adfoc.us'),
    forbid_shortener('adm.to'),
    forbid_shortener('adobe.ly'),
    forbid_shortener('adol.us'),
    forbid_shortener('adweek.it'),
    forbid_shortener('aet.na'),
    forbid_shortener('agrd.io'),
    forbid_shortener('ai6.net'),
    forbid_shortener('aje.io'),
    forbid_shortener('aka.ms'),
    forbid_shortener('al.st'),
    forbid_shortener('alexa.design'),
    forbid_shortener('alli.pub'),
    forbid_shortener('alnk.to'),
    forbid_shortener('alpha.camp'),
    forbid_shortener('alphab.gr'),
    forbid_shortener('alturl.com'),
    forbid_shortener('amays.im'),
    forbid_shortener('amba.to'),
    forbid_shortener('amc.film'),
    forbid_shortener('amex.co'),
    forbid_shortener('ampr.gs'),
    forbid_shortener('amrep.org'),
    forbid_shortener('amz.run'),
    forbid_shortener('amzn.com'),
    forbid_shortener('amzn.pw'),
    forbid_shortener('amzn.to'),
    forbid_shortener('ana.ms'),
    forbid_shortener('anch.co'),
    forbid_shortener('ancstry.me'),
    forbid_shortener('andauth.co'),
    forbid_shortener('anon.to'),
    forbid_shortener('anyimage.io'),
    forbid_shortener('aol.it'),
    forbid_shortener('aon.io'),
    forbid_shortener('apne.ws'),
    forbid_shortener('app.philz.us'),
    forbid_shortener('apple.co'),
    forbid_shortener('apple.news'),
    forbid_shortener('aptg.tw'),
    forbid_shortener('arah.in'),
    forbid_shortener('arc.ht'),
    forbid_shortener('arkinv.st'),
    forbid_shortener('asics.tv'),
    forbid_shortener('asin.cc'),
    forbid_shortener('asq.kr'),
    forbid_shortener('asus.click'),
    forbid_shortener('at.vibe.com'),
    forbid_shortener('atm.tk'),
    forbid_shortener('atmilb.com'),
    forbid_shortener('atmlb.com'),
    forbid_shortener('atres.red'),
    forbid_shortener('autode.sk'),
    forbid_shortener('avlne.ws'),
    forbid_shortener('avlr.co'),
    forbid_shortener('avydn.co'),
    forbid_shortener('axios.link'),
    forbid_shortener('axoni.us'),
    forbid_shortener('ay.gy'),
    forbid_shortener('azc.cc'),
    forbid_shortener('b-gat.es'),
    forbid_shortener('b.link'),
    forbid_shortener('b.mw'),
    forbid_shortener('b23.ru'),
    forbid_shortener('b23.tv'),
    forbid_shortener('b2n.ir'),
    forbid_shortener('baratun.de'),
    forbid_shortener('bayareane.ws'),
    forbid_shortener('bbc.in'),
    forbid_shortener('bbva.info'),
    forbid_shortener('bc.vc'),
    forbid_shortener('bca.id'),
    forbid_shortener('bcene.ws'),
    forbid_shortener('bcove.video'),
    forbid_shortener('bcsite.io'),
    forbid_shortener('bddy.me'),
    forbid_shortener('beats.is'),
    forbid_shortener('benqurl.biz'),
    forbid_shortener('beth.games'),
    forbid_shortener('bfpne.ws'),
    forbid_shortener('bg4.me'),
    forbid_shortener('bhpho.to'),
    forbid_shortener('bigcc.cc'),
    forbid_shortener('bigfi.sh'),
    forbid_shortener('biggo.tw'),
    forbid_shortener('biibly.com'),
    forbid_shortener('binged.it'),
    forbid_shortener('bit.do'),
    forbid_shortener('bit.ly'),
    forbid_shortener('bitly.com'),
    forbid_shortener('bitly.is'),
    forbid_shortener('bitly.lc'),
    forbid_shortener('bityl.co'),
    forbid_shortener('bl.ink'),
    forbid_shortener('blap.net'),
    forbid_shortener('blbrd.cm'),
    forbid_shortener('blck.by'),
    forbid_shortener('blizz.ly'),
    forbid_shortener('bloom.bg'),
    forbid_shortener('blstg.news'),
    forbid_shortener('blur.by'),
    forbid_shortener('bmai.cc'),
    forbid_shortener('bnds.in'),
    forbid_shortener('bnetwhk.com'),
    forbid_shortener('bo.st'),
    forbid_shortener('boa.la'),
    forbid_shortener('boile.rs'),
    forbid_shortener('bom.so'),
    forbid_shortener('bonap.it'),
    forbid_shortener('booki.ng'),
    forbid_shortener('bookstw.link'),
    forbid_shortener('bose.life'),
    forbid_shortener('boston25.com'),
    forbid_shortener('bp.cool'),
    forbid_shortener('br4.in'),
    forbid_shortener('bravo.ly'),
    forbid_shortener('bridge.dev'),
    forbid_shortener('brief.ly'),
    forbid_shortener('brook.gs'),
    forbid_shortener('browser.to'),
    forbid_shortener('bst.bz'),
    forbid_shortener('bstk.me'),
    forbid_shortener('btm.li'),
    forbid_shortener('btwrdn.com'),
    forbid_shortener('budurl.com'),
    forbid_shortener('buff.ly'),
    forbid_shortener('bung.ie'),
    forbid_shortener('buzurl.com'),
    forbid_shortener('bwnews.pr'),
    forbid_shortener('by2.io'),
    forbid_shortener('bytl.fr'),
    forbid_shortener('bzfd.it'),
    forbid_shortener('bzh.me'),
    forbid_shortener('c11.kr'),
    forbid_shortener('c87.to'),
    forbid_shortener('cadill.ac'),
    forbid_shortener('can.al'),
    forbid_shortener('canon.us'),
    forbid_shortener('capital.one'),
    forbid_shortener('capitalfm.co'),
    forbid_shortener('captl1.co'),
    forbid_shortener('careem.me'),
    forbid_shortener('caro.sl'),
    forbid_shortener('cart.mn'),
    forbid_shortener('casio.link'),
    forbid_shortener('cathaybk.tw'),
    forbid_shortener('cathaysec.tw'),
    forbid_shortener('cb.com'),
    forbid_shortener('cbj.co'),
    forbid_shortener('cbsloc.al'),
    forbid_shortener('cbsn.ws'),
    forbid_shortener('cbt.gg'),
    forbid_shortener('cc.cc'),
    forbid_shortener('cdl.booksy.com'),
    forbid_shortener('centi.ai'),
    forbid_shortener('cfl.re'),
    forbid_shortener('chip.tl'),
    forbid_shortener('chl.li'),
    forbid_shortener('chn.ge'),
    forbid_shortener('chn.lk'),
    forbid_shortener('chng.it'),
    forbid_shortener('chts.tw'),
    forbid_shortener('chzb.gr'),
    forbid_shortener('cin.ci'),
    forbid_shortener('cindora.club'),
    forbid_shortener('circle.ci'),
    forbid_shortener('cirk.me'),
    forbid_shortener('cisn.co'),
    forbid_shortener('citi.asia'),
    forbid_shortener('cjky.it'),
    forbid_shortener('ckbe.at'),
    forbid_shortener('cl.ly'),
    forbid_shortener('clarobr.co'),
    forbid_shortener('clc.am'),
    forbid_shortener('clc.to'),
    forbid_shortener('clck.ru'),
    forbid_shortener('cle.clinic'),
    forbid_shortener('cli.gs'),
    forbid_shortener('cli.re'),
    forbid_shortener('clickmeter.com'),
    forbid_shortener('clicky.me'),
    forbid_shortener('clr.tax'),
    forbid_shortener('clvr.rocks'),
    forbid_shortener('cmon.co'),
    forbid_shortener('cmu.is'),
    forbid_shortener('cmy.tw'),
    forbid_shortener('cna.asia'),
    forbid_shortener('cnb.cx'),
    forbid_shortener('cnet.co'),
    forbid_shortener('cnfl.io'),
    forbid_shortener('cnn.it'),
    forbid_shortener('cnnmon.ie'),
    forbid_shortener('cnvrge.co'),
    forbid_shortener('cockroa.ch'),
    forbid_shortener('comca.st'),
    forbid_shortener('come.ac'),
    forbid_shortener('conta.cc'),
    forbid_shortener('cookcenter.info'),
    forbid_shortener('coop.uk'),
    forbid_shortener('cort.as'),
    forbid_shortener('coupa.ng'),
    forbid_shortener('cplink.co'),
    forbid_shortener('cr8.lv'),
    forbid_shortener('crackm.ag'),
    forbid_shortener('crdrv.co'),
    forbid_shortener('credicard.biz'),
    forbid_shortener('crwd.fr'),
    forbid_shortener('crwd.in'),
    forbid_shortener('crwdstr.ke'),
    forbid_shortener('cs.co'),
    forbid_shortener('csmo.us'),
    forbid_shortener('cstu.io'),
    forbid_shortener('ctbc.tw'),
    forbid_shortener('ctfl.io'),
    forbid_shortener('cultm.ac'),
    forbid_shortener('cup.org'),
    forbid_shortener('cur.lv'),
    forbid_shortener('cut.lu'),
    forbid_shortener('cut.pe'),
    forbid_shortener('cutt.ly'),
    forbid_shortener('cutt.us'),
    forbid_shortener('cvent.me'),
    forbid_shortener('cvs.co'),
    forbid_shortener('cyb.ec'),
    forbid_shortener('cybr.rocks'),
    forbid_shortener('d-sh.io'),
    forbid_shortener('da.gd'),
    forbid_shortener('dai.ly'),
    forbid_shortener('dailym.ai'),
    forbid_shortener('dainik-b.in'),
    forbid_shortener('datayi.cn'),
    forbid_shortener('davidbombal.wiki'),
    forbid_shortener('db.tt'),
    forbid_shortener('dbricks.co'),
    forbid_shortener('dcps.co'),
    forbid_shortener('dd.ma'),
    forbid_shortener('deb.li'),
    forbid_shortener('dee.pl'),
    forbid_shortener('deli.bz'),
    forbid_shortener('dell.to'),
    forbid_shortener('deloi.tt'),
    forbid_shortener('dems.me'),
    forbid_shortener('dhk.gg'),
    forbid_shortener('di.sn'),
    forbid_shortener('dibb.me'),
    forbid_shortener('dis.gd'),
    forbid_shortener('dis.tl'),
    forbid_shortener('discord.gg'),
    forbid_shortener('discvr.co'),
    forbid_shortener('disq.us'),
    forbid_shortener('dive.pub'),
    forbid_shortener('dk.rog.gg'),
    forbid_shortener('dkng.co'),
    forbid_shortener('dky.bz'),
    forbid_shortener('dl.gl'),
    forbid_shortener('dld.bz'),
    forbid_shortener('dlsh.it'),
    forbid_shortener('dlvr.it'),
    forbid_shortener('dmdi.pl'),
    forbid_shortener('dmreg.co'),
    forbid_shortener('do.co'),
    forbid_shortener('dockr.ly'),
    forbid_shortener('dopice.sk'),
    forbid_shortener('dpmd.ai'),
    forbid_shortener('dpo.st'),
    forbid_shortener('dssurl.com'),
    forbid_shortener('dtdg.co'),
    forbid_shortener('dtsx.io'),
    forbid_shortener('dub.sh'),
    forbid_shortener('dv.gd'),
    forbid_shortener('dvrv.ai'),
    forbid_shortener('dw.com'),
    forbid_shortener('dwz.tax'),
    forbid_shortener('dxc.to'),
    forbid_shortener('dy.fi'),
    forbid_shortener('dy.si'),
    forbid_shortener('e.lilly'),
    forbid_shortener('e.vg'),
    forbid_shortener('ebay.to'),
    forbid_shortener('econ.st'),
    forbid_shortener('ed.gr'),
    forbid_shortener('edin.ac'),
    forbid_shortener('edu.nl'),
    forbid_shortener('eepurl.com'),
    forbid_shortener('efshop.tw'),
    forbid_shortener('ela.st'),
    forbid_shortener('elle.re'),
    forbid_shortener('ellemag.co'),
    forbid_shortener('embt.co'),
    forbid_shortener('emirat.es'),
    forbid_shortener('engt.co'),
    forbid_shortener('enshom.link'),
    forbid_shortener('entm.ag'),
    forbid_shortener('envs.sh'),
    forbid_shortener('epochtim.es'),
    forbid_shortener('ept.ms'),
    forbid_shortener('eqix.it'),
    forbid_shortener('es.pn'),
    forbid_shortener('es.rog.gg'),
    forbid_shortener('escape.to'),
    forbid_shortener('esl.gg'),
    forbid_shortener('eslite.me'),
    forbid_shortener('esqr.co'),
    forbid_shortener('esun.co'),
    forbid_shortener('etoro.tw'),
    forbid_shortener('etp.tw'),
    forbid_shortener('etsy.me'),
    forbid_shortener('everri.ch'),
    forbid_shortener('exe.io'),
    forbid_shortener('exitl.ag'),
    forbid_shortener('ezstat.ru'),
    forbid_shortener('f1.com'),
    forbid_shortener('f5yo.com'),
    forbid_shortener('fa.by'),
    forbid_shortener('fal.cn'),
    forbid_shortener('fam.ag'),
    forbid_shortener('fandan.co'),
    forbid_shortener('fandom.link'),
    forbid_shortener('fandw.me'),
    forbid_shortener('faras.link'),
    forbid_shortener('faturl.com'),
    forbid_shortener('fav.me'),
    forbid_shortener('fave.co'),
    forbid_shortener('fb.me'),
    forbid_shortener('fb.watch'),
    forbid_shortener('fbstw.link'),
    forbid_shortener('fce.gg'),
    forbid_shortener('fetnet.tw'),
    forbid_shortener('fevo.me'),
    forbid_shortener('ff.im'),
    forbid_shortener('fifa.fans'),
    forbid_shortener('filoops.info'),
    forbid_shortener('firsturl.de'),
    forbid_shortener('firsturl.net'),
    forbid_shortener('flic.kr'),
    forbid_shortener('flip.it'),
    forbid_shortener('flomuz.io'),
    forbid_shortener('flq.us'),
    forbid_shortener('fltr.ai'),
    forbid_shortener('flx.to'),
    forbid_shortener('fmurl.cc'),
    forbid_shortener('fn.gg'),
    forbid_shortener('fnb.lc'),
    forbid_shortener('foodtv.com'),
    forbid_shortener('fooji.info'),
    forbid_shortener('ford.to'),
    forbid_shortener('forms.gle'),
    forbid_shortener('forr.com'),
    forbid_shortener('found.ee'),
    forbid_shortener('fox.tv'),
    forbid_shortener('fr.rog.gg'),
    forbid_shortener('frdm.mobi'),
    forbid_shortener('fstrk.cc'),
    forbid_shortener('ftnt.net'),
    forbid_shortener('fumacrom.com'),
    forbid_shortener('fvrr.co'),
    forbid_shortener('fwme.eu'),
    forbid_shortener('fxn.ws'),
    forbid_shortener('g-web.in'),
    forbid_shortener('g.asia'),
    forbid_shortener('g.co'),
    forbid_shortener('g.page'),
    forbid_shortener('ga.co'),
    forbid_shortener('gandi.link'),
    forbid_shortener('garyvee.com'),
    forbid_shortener('gaw.kr'),
    forbid_shortener('gbod.org'),
    forbid_shortener('gbpg.net'),
    forbid_shortener('gbte.tech'),
    forbid_shortener('gdurl.com'),
    forbid_shortener('gek.link'),
    forbid_shortener('gen.cat'),
    forbid_shortener('geni.us'),
    forbid_shortener('genie.co.kr'),
    forbid_shortener('getf.ly'),
    forbid_shortener('geti.in'),
    forbid_shortener('gfuel.ly'),
    forbid_shortener('gh.io'),
    forbid_shortener('ghkp.us'),
    forbid_shortener('gi.lt'),
    forbid_shortener('gigaz.in'),
    forbid_shortener('git.io'),
    forbid_shortener('github.co'),
    forbid_shortener('gizmo.do'),
    forbid_shortener('gjk.id'),
    forbid_shortener('glblctzn.co'),
    forbid_shortener('glblctzn.me'),
    forbid_shortener('gldr.co'),
    forbid_shortener('glmr.co'),
    forbid_shortener('glo.bo'),
    forbid_shortener('gma.abc'),
    forbid_shortener('gmj.tw'),
    forbid_shortener('go-link.ru'),
    forbid_shortener('go.aws'),
    forbid_shortener('go.btwrdn.co'),
    forbid_shortener('go.cwtv.com'),
    forbid_shortener('go.dbs.com'),
    forbid_shortener('go.edh.tw'),
    forbid_shortener('go.gcash.com'),
    forbid_shortener('go.hny.co'),
    forbid_shortener('go.id.me'),
    forbid_shortener('go.intel-academy.com'),
    forbid_shortener('go.intigriti.com'),
    forbid_shortener('go.jc.fm'),
    forbid_shortener('go.lamotte.fr'),
    forbid_shortener('go.lu-h.de'),
    forbid_shortener('go.ly'),
    forbid_shortener('go.nasa.gov'),
    forbid_shortener('go.nowth.is'),
    forbid_shortener('go.osu.edu'),
    forbid_shortener('go.qb.by'),
    forbid_shortener('go.rebel.pl'),
    forbid_shortener('go.shell.com'),
    forbid_shortener('go.shr.lc'),
    forbid_shortener('go.sony.tw'),
    forbid_shortener('go.tinder.com'),
    forbid_shortener('go.usa.gov'),
    forbid_shortener('go.ustwo.games'),
    forbid_shortener('go.vic.gov.au'),
    forbid_shortener('godrk.de'),
    forbid_shortener('gofund.me'),
    forbid_shortener('gomomento.co'),
    forbid_shortener('goo-gl.me'),
    forbid_shortener('goo.by'),
    forbid_shortener('goo.gl'),
    forbid_shortener('goo.gle'),
    forbid_shortener('goo.su'),
    forbid_shortener('goolink.cc'),
    forbid_shortener('goolnk.com'),
    forbid_shortener('gosm.link'),
    forbid_shortener('got.cr'),
    forbid_shortener('got.to'),
    forbid_shortener('gov.tw'),
    forbid_shortener('gowat.ch'),
    forbid_shortener('gph.to'),
    forbid_shortener('gq.mn'),
    forbid_shortener('gr.pn'),
    forbid_shortener('grb.to'),
    forbid_shortener('grdt.ai'),
    forbid_shortener('grm.my'),
    forbid_shortener('grnh.se'),
    forbid_shortener('gtly.ink'),
    forbid_shortener('gtly.to'),
    forbid_shortener('gtne.ws'),
    forbid_shortener('gtnr.it'),
    forbid_shortener('gym.sh'),
    forbid_shortener('haa.su'),
    forbid_shortener('han.gl'),
    forbid_shortener('hashi.co'),
    forbid_shortener('hbaz.co'),
    forbid_shortener('hbom.ax'),
    forbid_shortener('her.is'),
    forbid_shortener('herff.ly'),
    forbid_shortener('hf.co'),
    forbid_shortener('hi.kktv.to'),
    forbid_shortener('hi.sat.cool'),
    forbid_shortener('hi.switchy.io'),
    forbid_shortener('hicider.com'),
    forbid_shortener('hideout.cc'),
    forbid_shortener('hill.cm'),
    forbid_shortener('histori.ca'),
    forbid_shortener('hmt.ai'),
    forbid_shortener('hnsl.mn'),
    forbid_shortener('homes.jp'),
    forbid_shortener('hp.care'),
    forbid_shortener('hpe.to'),
    forbid_shortener('hrbl.me'),
    forbid_shortener('href.li'),
    forbid_shortener('ht.ly'),
    forbid_shortener('htgb.co'),
    forbid_shortener('htl.li'),
    forbid_shortener('htn.to'),
    forbid_shortener('httpslink.com'),
    forbid_shortener('hubs.la'),
    forbid_shortener('hubs.li'),
    forbid_shortener('hubs.ly'),
    forbid_shortener('huffp.st'),
    forbid_shortener('hulu.tv'),
    forbid_shortener('huma.na'),
    forbid_shortener('hyperurl.co'),
    forbid_shortener('hyperx.gg'),
    forbid_shortener('i-d.co'),
    forbid_shortener('i.coscup.org'),
    forbid_shortener('i.mtr.cool'),
    forbid_shortener('ibb.co'),
    forbid_shortener('ibf.tw'),
    forbid_shortener('ibit.ly'),
    forbid_shortener('ibm.biz'),
    forbid_shortener('ibm.co'),
    forbid_shortener('ic9.in'),
    forbid_shortener('icit.fr'),
    forbid_shortener('icks.ro'),
    forbid_shortener('iea.li'),
    forbid_shortener('ifix.gd'),
    forbid_shortener('ift.tt'),
    forbid_shortener('iherb.co'),
    forbid_shortener('ihr.fm'),
    forbid_shortener('ii1.su'),
    forbid_shortener('iii.im'),
    forbid_shortener('il.rog.gg'),
    forbid_shortener('ilang.in'),
    forbid_shortener('illin.is'),
    forbid_shortener('iln.io'),
    forbid_shortener('ilnk.io'),
    forbid_shortener('imdb.to'),
    forbid_shortener('ind.pn'),
    forbid_shortener('indeedhi.re'),
    forbid_shortener('indy.st'),
    forbid_shortener('infy.com'),
    forbid_shortener('inlnk.ru'),
    forbid_shortener('insig.ht'),
    forbid_shortener('instagr.am'),
    forbid_shortener('intel.ly'),
    forbid_shortener('interc.pt'),
    forbid_shortener('intuit.me'),
    forbid_shortener('invent.ge'),
    forbid_shortener('inx.lv'),
    forbid_shortener('ionos.ly'),
    forbid_shortener('ipgrabber.ru'),
    forbid_shortener('ipgraber.ru'),
    forbid_shortener('iplogger.co'),
    forbid_shortener('iplogger.com'),
    forbid_shortener('iplogger.info'),
    forbid_shortener('iplogger.org'),
    forbid_shortener('iplogger.ru'),
    forbid_shortener('iplwin.us'),
    forbid_shortener('iqiyi.cn'),
    forbid_shortener('irng.ca'),
    forbid_shortener('is.gd'),
    forbid_shortener('isw.pub'),
    forbid_shortener('itsh.bo'),
    forbid_shortener('itvty.com'),
    forbid_shortener('ity.im'),
    forbid_shortener('ix.sk'),
    forbid_shortener('j.gs'),
    forbid_shortener('j.mp'),
    forbid_shortener('ja.cat'),
    forbid_shortener('ja.ma'),
    forbid_shortener('jb.gg'),
    forbid_shortener('jcp.is'),
    forbid_shortener('jkf.lv'),
    forbid_shortener('jnfusa.org'),
    forbid_shortener('jp.rog.gg'),
    forbid_shortener('jpeg.ly'),
    forbid_shortener('jz.rs'),
    forbid_shortener('k-p.li'),
    forbid_shortener('kas.pr'),
    forbid_shortener('kask.us'),
    forbid_shortener('katzr.net'),
    forbid_shortener('kbank.co'),
    forbid_shortener('kck.st'),
    forbid_shortener('kf.org'),
    forbid_shortener('kfrc.co'),
    forbid_shortener('kg.games'),
    forbid_shortener('kgs.link'),
    forbid_shortener('kham.tw'),
    forbid_shortener('kings.tn'),
    forbid_shortener('kkc.tech'),
    forbid_shortener('kkday.me'),
    forbid_shortener('kkne.ws'),
    forbid_shortener('kko.to'),
    forbid_shortener('kkstre.am'),
    forbid_shortener('kl.ik.my'),
    forbid_shortener('klck.me'),
    forbid_shortener('kli.cx'),
    forbid_shortener('klmf.ly'),
    forbid_shortener('ko.gl'),
    forbid_shortener('kortlink.dk'),
    forbid_shortener('kotl.in'),
    forbid_shortener('kp.org'),
    forbid_shortener('kpmg.ch'),
    forbid_shortener('krazy.la'),
    forbid_shortener('kuku.lu'),
    forbid_shortener('kurl.ru'),
    forbid_shortener('kutt.it'),
    forbid_shortener('ky77.link'),
    forbid_shortener('l.gg'),
    forbid_shortener('l.linklyhq.com'),
    forbid_shortener('l.prageru.com'),
    forbid_shortener('l8r.it'),
    forbid_shortener('laco.st'),
    forbid_shortener('lam.bo'),
    forbid_shortener('lat.ms'),
    forbid_shortener('latingram.my'),
    forbid_shortener('lativ.tw'),
    forbid_shortener('lbtw.tw'),
    forbid_shortener('lc.cx'),
    forbid_shortener('learn.to'),
    forbid_shortener('lego.build'),
    forbid_shortener('lemde.fr'),
    forbid_shortener('letsharu.cc'),
    forbid_shortener('lft.to'),
    forbid_shortener('lih.kg'),
    forbid_shortener('lihi.biz'),
    forbid_shortener('lihi.cc'),
    forbid_shortener('lihi.one'),
    forbid_shortener('lihi.pro'),
    forbid_shortener('lihi.tv'),
    forbid_shortener('lihi.vip'),
    forbid_shortener('lihi1.cc'),
    forbid_shortener('lihi1.com'),
    forbid_shortener('lihi1.me'),
    forbid_shortener('lihi2.cc'),
    forbid_shortener('lihi2.com'),
    forbid_shortener('lihi2.me'),
    forbid_shortener('lihi3.cc'),
    forbid_shortener('lihi3.com'),
    forbid_shortener('lihi3.me'),
    forbid_shortener('lihipro.com'),
    forbid_shortener('lihivip.com'),
    forbid_shortener('liip.to'),
    forbid_shortener('lin.ee'),
    forbid_shortener('lin0.de'),
    forbid_shortener('link.ac'),
    forbid_shortener('link.europa.eu'),
    forbid_shortener('link.infini.fr'),
    forbid_shortener('link.tubi.tv'),
    forbid_shortener('linkbun.com'),
    forbid_shortener('linkd.in'),
    forbid_shortener('linkjust.com'),
    forbid_shortener('linko.page'),
    forbid_shortener('linkopener.co'),
    forbid_shortener('links2.me'),
    forbid_shortener('linkshare.pro'),
    forbid_shortener('linkye.net'),
    forbid_shortener('livemu.sc'),
    forbid_shortener('livestre.am'),
    forbid_shortener('llk.dk'),
    forbid_shortener('llo.to'),
    forbid_shortener('lmg.gg'),
    forbid_shortener('lmt.co'),
    forbid_shortener('lmy.de'),
    forbid_shortener('ln.run'),
    forbid_shortener('lnk.bz'),
    forbid_shortener('lnk.direct'),
    forbid_shortener('lnk.do'),
    forbid_shortener('lnk.sk'),
    forbid_shortener('lnkd.in'),
    forbid_shortener('lnkiy.com'),
    forbid_shortener('lnkiy.in'),
    forbid_shortener('lnky.jp'),
    forbid_shortener('lnnk.in'),
    forbid_shortener('lnv.gy'),
    forbid_shortener('lohud.us'),
    forbid_shortener('lonerwolf.co'),
    forbid_shortener('loom.ly'),
    forbid_shortener('low.es'),
    forbid_shortener('lprk.co'),
    forbid_shortener('lru.jp'),
    forbid_shortener('lsdl.es'),
    forbid_shortener('lstu.fr'),
    forbid_shortener('lt27.de'),
    forbid_shortener('lttr.ai'),
    forbid_shortener('ludia.gg'),
    forbid_shortener('luminary.link'),
    forbid_shortener('lurl.cc'),
    forbid_shortener('lyksoomu.com'),
    forbid_shortener('lzd.co'),
    forbid_shortener('m.me'),
    forbid_shortener('m.tb.cn'),
    forbid_shortener('m101.org'),
    forbid_shortener('m1p.fr'),
    forbid_shortener('maac.io'),
    forbid_shortener('maga.lu'),
    forbid_shortener('man.ac.uk'),
    forbid_shortener('many.at'),
    forbid_shortener('maper.info'),
    forbid_shortener('mapfan.to'),
    forbid_shortener('mayocl.in'),
    forbid_shortener('mbapp.io'),
    forbid_shortener('mbayaq.co'),
    forbid_shortener('mcafee.ly'),
    forbid_shortener('mcd.to'),
    forbid_shortener('mcgam.es'),
    forbid_shortener('mck.co'),
    forbid_shortener('mcys.co'),
    forbid_shortener('me.sv'),
    forbid_shortener('me2.kr'),
    forbid_shortener('meck.co'),
    forbid_shortener('meetu.ps'),
    forbid_shortener('merky.de'),
    forbid_shortener('metamark.net'),
    forbid_shortener('mgnet.me'),
    forbid_shortener('mgstn.ly'),
    forbid_shortener('michmed.org'),
    forbid_shortener('migre.me'),
    forbid_shortener('minify.link'),
    forbid_shortener('minilink.io'),
    forbid_shortener('mitsha.re'),
    forbid_shortener('mklnd.com'),
    forbid_shortener('mm.rog.gg'),
    forbid_shortener('mney.co'),
    forbid_shortener('mng.bz'),
    forbid_shortener('mnge.it'),
    forbid_shortener('mnot.es'),
    forbid_shortener('mo.ma'),
    forbid_shortener('momo.dm'),
    forbid_shortener('monster.cat'),
    forbid_shortener('moo.im'),
    forbid_shortener('moourl.com'),
    forbid_shortener('moovit.me'),
    forbid_shortener('mork.ro'),
    forbid_shortener('mou.sr'),
    forbid_shortener('mpl.pm'),
    forbid_shortener('mrte.ch'),
    forbid_shortener('mrx.cl'),
    forbid_shortener('ms.spr.ly'),
    forbid_shortener('msft.it'),
    forbid_shortener('msi.gm'),
    forbid_shortener('mstr.cl'),
    forbid_shortener('mttr.io'),
    forbid_shortener('mub.me'),
    forbid_shortener('munbyn.biz'),
    forbid_shortener('mvmtwatch.co'),
    forbid_shortener('my.mtr.cool'),
    forbid_shortener('mybmw.tw'),
    forbid_shortener('myglamm.in'),
    forbid_shortener('mylt.tv'),
    forbid_shortener('mypoya.com'),
    forbid_shortener('myppt.cc'),
    forbid_shortener('mysp.ac'),
    forbid_shortener('myumi.ch'),
    forbid_shortener('myurls.ca'),
    forbid_shortener('mz.cm'),
    forbid_shortener('mzl.la'),
    forbid_shortener('n.opn.tl'),
    forbid_shortener('n.pr'),
    forbid_shortener('n9.cl'),
    forbid_shortener('name.ly'),
    forbid_shortener('nature.ly'),
    forbid_shortener('nav.cx'),
    forbid_shortener('naver.me'),
    forbid_shortener('nbc4dc.com'),
    forbid_shortener('nbcbay.com'),
    forbid_shortener('nbcchi.com'),
    forbid_shortener('nbcct.co'),
    forbid_shortener('nbcnews.to'),
    forbid_shortener('nbzp.cz'),
    forbid_shortener('nchcnh.info'),
    forbid_shortener('nej.md'),
    forbid_shortener('neti.cc'),
    forbid_shortener('netm.ag'),
    forbid_shortener('nflx.it'),
    forbid_shortener('ngrid.com'),
    forbid_shortener('njersy.co'),
    forbid_shortener('nkbp.jp'),
    forbid_shortener('nkf.re'),
    forbid_shortener('nmrk.re'),
    forbid_shortener('nnn.is'),
    forbid_shortener('nnna.ru'),
    forbid_shortener('nokia.ly'),
    forbid_shortener('notlong.com'),
    forbid_shortener('nr.tn'),
    forbid_shortener('nswroads.work'),
    forbid_shortener('ntap.com'),
    forbid_shortener('ntck.co'),
    forbid_shortener('ntn.so'),
    forbid_shortener('ntuc.co'),
    forbid_shortener('nus.edu'),
    forbid_shortener('nvda.ws'),
    forbid_shortener('nwppr.co'),
    forbid_shortener('nwsdy.li'),
    forbid_shortener('nxb.tw'),
    forbid_shortener('nxdr.co'),
    forbid_shortener('nycu.to'),
    forbid_shortener('nydn.us'),
    forbid_shortener('nyer.cm'),
    forbid_shortener('nyp.st'),
    forbid_shortener('nyr.kr'),
    forbid_shortener('nyti.ms'),
    forbid_shortener('o.vg'),
    forbid_shortener('oal.lu'),
    forbid_shortener('obank.tw'),
    forbid_shortener('ock.cn'),
    forbid_shortener('ocul.us'),
    forbid_shortener('oe.cd'),
    forbid_shortener('ofcour.se'),
    forbid_shortener('offerup.co'),
    forbid_shortener('offf.to'),
    forbid_shortener('offs.ec'),
    forbid_shortener('okt.to'),
    forbid_shortener('omni.ag'),
    forbid_shortener('on.bcg.com'),
    forbid_shortener('on.bp.com'),
    forbid_shortener('on.fb.me'),
    forbid_shortener('on.ft.com'),
    forbid_shortener('on.louisvuitton.com'),
    forbid_shortener('on.mktw.net'),
    forbid_shortener('on.natgeo.com'),
    forbid_shortener('on.nba.com'),
    forbid_shortener('on.ny.gov'),
    forbid_shortener('on.nyc.gov'),
    forbid_shortener('on.nypl.org'),
    forbid_shortener('on.tcs.com'),
    forbid_shortener('on.wsj.com'),
    forbid_shortener('on9news.tv'),
    forbid_shortener('onelink.to'),
    forbid_shortener('onepl.us'),
    forbid_shortener('onforb.es'),
    forbid_shortener('onion.com'),
    forbid_shortener('onx.la'),
    forbid_shortener('oow.pw'),
    forbid_shortener('opr.as'),
    forbid_shortener('opr.news'),
    forbid_shortener('optimize.ly'),
    forbid_shortener('oran.ge'),
    forbid_shortener('orlo.uk'),
    forbid_shortener('osdb.link'),
    forbid_shortener('oshko.sh'),
    forbid_shortener('ouo.io'),
    forbid_shortener('ouo.press'),
    forbid_shortener('ourl.co'),
    forbid_shortener('ourl.in'),
    forbid_shortener('ourl.tw'),
    forbid_shortener('outschooler.me'),
    forbid_shortener('ovh.to'),
    forbid_shortener('ow.ly'),
    forbid_shortener('owl.li'),
    forbid_shortener('owy.mn'),
    forbid_shortener('oxelt.gl'),
    forbid_shortener('oxf.am'),
    forbid_shortener('oyn.at'),
    forbid_shortener('p.asia'),
    forbid_shortener('p.dw.com'),
    forbid_shortener('p1r.es'),
    forbid_shortener('p4k.in'),
    forbid_shortener('pa.ag'),
    forbid_shortener('packt.link'),
    forbid_shortener('pag.la'),
    forbid_shortener('para.pt'),
    forbid_shortener('pchome.link'),
    forbid_shortener('pck.tv'),
    forbid_shortener('pdora.co'),
    forbid_shortener('pdxint.at'),
    forbid_shortener('pe.ga'),
    forbid_shortener('pens.pe'),
    forbid_shortener('peoplem.ag'),
    forbid_shortener('pepsi.co'),
    forbid_shortener('pesc.pw'),
    forbid_shortener('petrobr.as'),
    forbid_shortener('pew.org'),
    forbid_shortener('pewrsr.ch'),
    forbid_shortener('pg3d.app'),
    forbid_shortener('pgat.us'),
    forbid_shortener('pgrs.in'),
    forbid_shortener('philips.to'),
    forbid_shortener('piee.pw'),
    forbid_shortener('pin.it'),
    forbid_shortener('pipr.es'),
    forbid_shortener('pj.pizza'),
    forbid_shortener('pl.kotl.in'),
    forbid_shortener('pldthome.info'),
    forbid_shortener('plu.sh'),
    forbid_shortener('pnsne.ws'),
    forbid_shortener('po.st'),
    forbid_shortener('pod.fo'),
    forbid_shortener('poie.ma'),
    forbid_shortener('pojonews.co'),
    forbid_shortener('politi.co'),
    forbid_shortener('popm.ch'),
    forbid_shortener('posh.mk'),
    forbid_shortener('pplx.ai'),
    forbid_shortener('ppt.cc'),
    forbid_shortener('ppurl.io'),
    forbid_shortener('pr.tn'),
    forbid_shortener('prbly.us'),
    forbid_shortener('prdct.school'),
    forbid_shortener('preml.ge'),
    forbid_shortener('prf.hn'),
    forbid_shortener('prgress.co'),
    forbid_shortener('prn.to'),
    forbid_shortener('propub.li'),
    forbid_shortener('pros.is'),
    forbid_shortener('psce.pw'),
    forbid_shortener('pse.is'),
    forbid_shortener('psee.io'),
    forbid_shortener('pt.rog.gg'),
    forbid_shortener('ptix.co'),
    forbid_shortener('puext.in'),
    forbid_shortener('purdue.university'),
    forbid_shortener('purefla.sh'),
    forbid_shortener('puri.na'),
    forbid_shortener('pwc.to'),
    forbid_shortener('pxgo.net'),
    forbid_shortener('pxu.co'),
    forbid_shortener('pzdls.co'),
    forbid_shortener('q.gs'),
    forbid_shortener('qnap.to'),
    forbid_shortener('qptr.ru'),
    forbid_shortener('qr.ae'),
    forbid_shortener('qr.net'),
    forbid_shortener('qrco.de'),
    forbid_shortener('qrs.ly'),
    forbid_shortener('qvc.co'),
    forbid_shortener('r-7.co'),
    forbid_shortener('r.zecz.ec'),
    forbid_shortener('rb.gy'),
    forbid_shortener('rbl.ms'),
    forbid_shortener('rblx.co'),
    forbid_shortener('rch.lt'),
    forbid_shortener('rd.gt'),
    forbid_shortener('rdbl.co'),
    forbid_shortener('rdcrss.org'),
    forbid_shortener('rdcu.be'),
    forbid_shortener('rdlnk.com'),
    forbid_shortener('read.bi'),
    forbid_shortener('readhacker.news'),
    forbid_shortener('rebelne.ws'),
    forbid_shortener('rebrand.ly'),
    forbid_shortener('reconis.co'),
    forbid_shortener('red.ht'),
    forbid_shortener('redaz.in'),
    forbid_shortener('redd.it'),
    forbid_shortener('redir.ec'),
    forbid_shortener('redir.is'),
    forbid_shortener('redsto.ne'),
    forbid_shortener('ref.trade.re'),
    forbid_shortener('refini.tv'),
    forbid_shortener('regmovi.es'),
    forbid_shortener('reline.cc'),
    forbid_shortener('relink.asia'),
    forbid_shortener('rem.ax'),
    forbid_shortener('renew.ge'),
    forbid_shortener('replug.link'),
    forbid_shortener('rethinktw.cc'),
    forbid_shortener('reurl.cc'),
    forbid_shortener('reut.rs'),
    forbid_shortener('rev.cm'),
    forbid_shortener('revr.ec'),
    forbid_shortener('rfr.bz'),
    forbid_shortener('ringcentr.al'),
    forbid_shortener('riot.com'),
    forbid_shortener('rip.city'),
    forbid_shortener('risu.io'),
    forbid_shortener('ritea.id'),
    forbid_shortener('rizy.ir'),
    forbid_shortener('rlu.ru'),
    forbid_shortener('rly.pt'),
    forbid_shortener('rnm.me'),
    forbid_shortener('ro.blox.com'),
    forbid_shortener('rog.gg'),
    forbid_shortener('roge.rs'),
    forbid_shortener('rol.st'),
    forbid_shortener('rotf.lol'),
    forbid_shortener('rozhl.as'),
    forbid_shortener('rpf.io'),
    forbid_shortener('rptl.io'),
    forbid_shortener('rsc.li'),
    forbid_shortener('rsh.md'),
    forbid_shortener('rtvote.com'),
    forbid_shortener('ru.rog.gg'),
    forbid_shortener('rushgiving.com'),
    forbid_shortener('rvtv.io'),
    forbid_shortener('rvwd.co'),
    forbid_shortener('rwl.io'),
    forbid_shortener('ryml.me'),
    forbid_shortener('rzr.to'),
    forbid_shortener('s.accupass.com'),
    forbid_shortener('s.coop'),
    forbid_shortener('s.ee'),
    forbid_shortener('s.g123.jp'),
    forbid_shortener('s.id'),
    forbid_shortener('s.mj.run'),
    forbid_shortener('s.ul.com'),
    forbid_shortener('s.uniqlo.com'),
    forbid_shortener('s.wikicharlie.cl'),
    forbid_shortener('s04.de'),
    forbid_shortener('s3vip.tw'),
    forbid_shortener('saf.li'),
    forbid_shortener('safelinking.net'),
    forbid_shortener('safl.it'),
    forbid_shortener('sail.to'),
    forbid_shortener('samcart.me'),
    forbid_shortener('sbird.co'),
    forbid_shortener('sbux.co'),
    forbid_shortener('sbux.jp'),
    forbid_shortener('sc.mp'),
    forbid_shortener('sc.org'),
    forbid_shortener('sched.co'),
    forbid_shortener('sck.io'),
    forbid_shortener('scr.bi'),
    forbid_shortener('scrb.ly'),
    forbid_shortener('scrnch.me'),
    forbid_shortener('scuf.co'),
    forbid_shortener('sdpbne.ws'),
    forbid_shortener('sdu.sk'),
    forbid_shortener('sdut.us'),
    forbid_shortener('se.rog.gg'),
    forbid_shortener('seagate.media'),
    forbid_shortener('sealed.in'),
    forbid_shortener('seedsta.rs'),
    forbid_shortener('seiu.co'),
    forbid_shortener('sejr.nl'),
    forbid_shortener('selnd.com'),
    forbid_shortener('seq.vc'),
    forbid_shortener('sf3c.tw'),
    forbid_shortener('sfca.re'),
    forbid_shortener('sfcne.ws'),
    forbid_shortener('sforce.co'),
    forbid_shortener('sfty.io'),
    forbid_shortener('sgq.io'),
    forbid_shortener('shar.as'),
    forbid_shortener('shiny.link'),
    forbid_shortener('shln.me'),
    forbid_shortener('sho.pe'),
    forbid_shortener('shope.ee'),
    forbid_shortener('shorl.com'),
    forbid_shortener('short.gy'),
    forbid_shortener('short.nr'),
    forbid_shortener('shorten.asia'),
    forbid_shortener('shorten.ee'),
    forbid_shortener('shorten.is'),
    forbid_shortener('shorten.so'),
    forbid_shortener('shorten.tv'),
    forbid_shortener('shorten.world'),
    forbid_shortener('shorter.me'),
    forbid_shortener('shorturl.ae'),
    forbid_shortener('shorturl.asia'),
    forbid_shortener('shorturl.at'),
    forbid_shortener('shorturl.com'),
    forbid_shortener('shorturl.gg'),
    forbid_shortener('shp.ee'),
    forbid_shortener('shrtm.nu'),
    forbid_shortener('sht.moe'),
    forbid_shortener('shutr.bz'),
    forbid_shortener('sie.ag'),
    forbid_shortener('simp.ly'),
    forbid_shortener('sina.lt'),
    forbid_shortener('sincere.ly'),
    forbid_shortener('sinourl.tw'),
    forbid_shortener('sinyi.biz'),
    forbid_shortener('sinyi.in'),
    forbid_shortener('siriusxm.us'),
    forbid_shortener('siteco.re'),
    forbid_shortener('sk.in.rs'),
    forbid_shortener('skimmth.is'),
    forbid_shortener('skl.sh'),
    forbid_shortener('skr.rs'),
    forbid_shortener('skrat.it'),
    forbid_shortener('skyurl.cc'),
    forbid_shortener('slidesha.re'),
    forbid_shortener('small.cat'),
    forbid_shortener('smart.link'),
    forbid_shortener('smarturl.it'),
    forbid_shortener('smashed.by'),
    forbid_shortener('smlk.es'),
    forbid_shortener('smsb.co'),
    forbid_shortener('smsng.news'),
    forbid_shortener('smsng.us'),
    forbid_shortener('smtvj.com'),
    forbid_shortener('smu.gs'),
    forbid_shortener('sn.im'),
    forbid_shortener('sn.rs'),
    forbid_shortener('snd.sc'),
    forbid_shortener('sndn.link'),
    forbid_shortener('snip.link'),
    forbid_shortener('snip.ly'),
    forbid_shortener('snipurl.com'),
    forbid_shortener('snyk.co'),
    forbid_shortener('so.arte'),
    forbid_shortener('soc.cr'),
    forbid_shortener('soch.us'),
    forbid_shortener('social.ora.cl'),
    forbid_shortener('socx.in'),
    forbid_shortener('sokrati.ru'),
    forbid_shortener('solsn.se'),
    forbid_shortener('sou.nu'),
    forbid_shortener('sourl.cn'),
    forbid_shortener('sovrn.co'),
    forbid_shortener('spcne.ws'),
    forbid_shortener('spgrp.sg'),
    forbid_shortener('spigen.co'),
    forbid_shortener('split.to'),
    forbid_shortener('splk.it'),
    forbid_shortener('spoti.fi'),
    forbid_shortener('spotify.link'),
    forbid_shortener('spr.ly'),
    forbid_shortener('spr.tn'),
    forbid_shortener('sprtsnt.ca'),
    forbid_shortener('sqex.to'),
    forbid_shortener('sqrx.io'),
    forbid_shortener('squ.re'),
    forbid_shortener('srnk.us'),
    forbid_shortener('ssur.cc'),
    forbid_shortener('st.news'),
    forbid_shortener('st8.fm'),
    forbid_shortener('stanford.io'),
    forbid_shortener('starz.tv'),
    forbid_shortener('stmodel.com'),
    forbid_shortener('storycor.ps'),
    forbid_shortener('stspg.io'),
    forbid_shortener('stts.in'),
    forbid_shortener('stuf.in'),
    forbid_shortener('su.pr'),
    forbid_shortener('sumal.ly'),
    forbid_shortener('suo.fyi'),
    forbid_shortener('suo.im'),
    forbid_shortener('supr.cl'),
    forbid_shortener('supr.link'),
    forbid_shortener('surl.li'),
    forbid_shortener('svy.mk'),
    forbid_shortener('swa.is'),
    forbid_shortener('swag.run'),
    forbid_shortener('swiy.co'),
    forbid_shortener('swoo.sh'),
    forbid_shortener('swtt.cc'),
    forbid_shortener('sy.to'),
    forbid_shortener('syb.la'),
    forbid_shortener('synd.co'),
    forbid_shortener('syw.co'),
    forbid_shortener('t-bi.link'),
    forbid_shortener('t-mo.co'),
    forbid_shortener('t.cn'),
    forbid_shortener('t.co'),
    forbid_shortener('t.iotex.me'),
    forbid_shortener('t.libren.ms'),
    forbid_shortener('t.ly'),
    forbid_shortener('t.tl'),
    forbid_shortener('t1p.de'),
    forbid_shortener('t2m.io'),
    forbid_shortener('ta.co'),
    forbid_shortener('tabsoft.co'),
    forbid_shortener('taiwangov.com'),
    forbid_shortener('tanks.ly'),
    forbid_shortener('tbb.tw'),
    forbid_shortener('tbrd.co'),
    forbid_shortener('tcrn.ch'),
    forbid_shortener('tdrive.li'),
    forbid_shortener('tdy.sg'),
    forbid_shortener('tek.io'),
    forbid_shortener('temu.to'),
    forbid_shortener('ter.li'),
    forbid_shortener('tg.pe'),
    forbid_shortener('tgam.ca'),
    forbid_shortener('tgr.ph'),
    forbid_shortener('thatis.me'),
    forbid_shortener('thd.co'),
    forbid_shortener('thedo.do'),
    forbid_shortener('thefp.pub'),
    forbid_shortener('thein.fo'),
    forbid_shortener('thesne.ws'),
    forbid_shortener('thetim.es'),
    forbid_shortener('thght.works'),
    forbid_shortener('thinfi.com'),
    forbid_shortener('thls.co'),
    forbid_shortener('thn.news'),
    forbid_shortener('thr.cm'),
    forbid_shortener('thrill.to'),
    forbid_shortener('ti.me'),
    forbid_shortener('tibco.cm'),
    forbid_shortener('tibco.co'),
    forbid_shortener('tidd.ly'),
    forbid_shortener('tim.com.vc'),
    forbid_shortener('tinu.be'),
    forbid_shortener('tiny.cc'),
    forbid_shortener('tiny.ee'),
    forbid_shortener('tiny.one'),
    forbid_shortener('tiny.pl'),
    forbid_shortener('tinyarro.ws'),
    forbid_shortener('tinyarrows.com'),
    forbid_shortener('tinylink.net'),
    forbid_shortener('tinyurl.com'),
    forbid_shortener('tinyurl.hu'),
    forbid_shortener('tinyurl.mobi'),
    forbid_shortener('tktwb.tw'),
    forbid_shortener('tl.gd'),
    forbid_shortener('tlil.nl'),
    forbid_shortener('tlrk.it'),
    forbid_shortener('tmblr.co'),
    forbid_shortener('tmsnrt.rs'),
    forbid_shortener('tmz.me'),
    forbid_shortener('tnne.ws'),
    forbid_shortener('tnsne.ws'),
    forbid_shortener('tnvge.co'),
    forbid_shortener('tnw.to'),
    forbid_shortener('tny.cz'),
    forbid_shortener('tny.im'),
    forbid_shortener('tny.so'),
    forbid_shortener('to.ly'),
    forbid_shortener('to.pbs.org'),
    forbid_shortener('toi.in'),
    forbid_shortener('tokopedia.link'),
    forbid_shortener('tonyr.co'),
    forbid_shortener('topt.al'),
    forbid_shortener('toyota.us'),
    forbid_shortener('tpc.io'),
    forbid_shortener('tpmr.com'),
    forbid_shortener('tprk.us'),
    forbid_shortener('tr.ee'),
    forbid_shortener('tr.im'),
    forbid_shortener('trackurl.link'),
    forbid_shortener('trade.re'),
    forbid_shortener('travl.rs'),
    forbid_shortener('trib.al'),
    forbid_shortener('trib.in'),
    forbid_shortener('troy.hn'),
    forbid_shortener('trt.sh'),
    forbid_shortener('trymongodb.com'),
    forbid_shortener('tsbk.tw'),
    forbid_shortener('tsta.rs'),
    forbid_shortener('tt.vg'),
    forbid_shortener('tvote.org'),
    forbid_shortener('tw.rog.gg'),
    forbid_shortener('tw.sv'),
    forbid_shortener('twb.nz'),
    forbid_shortener('tweez.me'),
    forbid_shortener('twitthis.com'),
    forbid_shortener('twm5g.co'),
    forbid_shortener('twou.co'),
    forbid_shortener('twurl.nl'),
    forbid_shortener('txdl.top'),
    forbid_shortener('txul.cn'),
    forbid_shortener('tyn.ee'),
    forbid_shortener('u.bb'),
    forbid_shortener('u.nu'),
    forbid_shortener('u.shxj.pw'),
    forbid_shortener('u.to'),
    forbid_shortener('u1.mnge.co'),
    forbid_shortener('ua.rog.gg'),
    forbid_shortener('uafly.co'),
    forbid_shortener('ubm.io'),
    forbid_shortener('ubnt.link'),
    forbid_shortener('ubr.to'),
    forbid_shortener('ucbexed.org'),
    forbid_shortener('ucla.in'),
    forbid_shortener('ufcqc.link'),
    forbid_shortener('ugp.io'),
    forbid_shortener('ui8.ru'),
    forbid_shortener('uk.rog.gg'),
    forbid_shortener('ukf.me'),
    forbid_shortener('ukoeln.de'),
    forbid_shortener('ul.rs'),
    forbid_shortener('ul.to'),
    forbid_shortener('ul3.ir'),
    forbid_shortener('ulvis.net'),
    forbid_shortener('ume.la'),
    forbid_shortener('umlib.us'),
    forbid_shortener('unc.live'),
    forbid_shortener('undrarmr.co'),
    forbid_shortener('uni.cf'),
    forbid_shortener('unipapa.co'),
    forbid_shortener('uofr.us'),
    forbid_shortener('uoft.me'),
    forbid_shortener('up.to'),
    forbid_shortener('upmchp.us'),
    forbid_shortener('ur1.ca'),
    forbid_shortener('ur3.us'),
    forbid_shortener('urb.tf'),
    forbid_shortener('urbn.is'),
    forbid_shortener('url.cn'),
    forbid_shortener('url.cy'),
    forbid_shortener('url.ie'),
    forbid_shortener('url2.fr'),
    forbid_shortener('urla.ru'),
    forbid_shortener('urlgeni.us'),
    forbid_shortener('urli.ai'),
    forbid_shortener('urlify.cn'),
    forbid_shortener('urlof.site'),
    forbid_shortener('urlr.me'),
    forbid_shortener('urls.fr'),
    forbid_shortener('urls.kr'),
    forbid_shortener('urluno.com'),
    forbid_shortener('urly.co'),
    forbid_shortener('urly.fi'),
    forbid_shortener('urlz.fr'),
    forbid_shortener('urlzs.com'),
    forbid_shortener('urt.io'),
    forbid_shortener('us.rog.gg'),
    forbid_shortener('usanet.tv'),
    forbid_shortener('usat.ly'),
    forbid_shortener('utm.to'),
    forbid_shortener('utn.pl'),
    forbid_shortener('utraker.com'),
    forbid_shortener('v.gd'),
    forbid_shortener('v.redd.it'),
    forbid_shortener('vbly.us'),
    forbid_shortener('vd55.com'),
    forbid_shortener('vercel.link'),
    forbid_shortener('vi.sa'),
    forbid_shortener('vi.tc'),
    forbid_shortener('viaalto.me'),
    forbid_shortener('viaja.am'),
    forbid_shortener('vineland.dj'),
    forbid_shortener('viraln.co'),
    forbid_shortener('vivo.tl'),
    forbid_shortener('vk.cc'),
    forbid_shortener('vk.sv'),
    forbid_shortener('vn.rog.gg'),
    forbid_shortener('vntyfr.com'),
    forbid_shortener('vo.la'),
    forbid_shortener('vodafone.uk'),
    forbid_shortener('vogue.cm'),
    forbid_shortener('voicetu.be'),
    forbid_shortener('volvocars.us'),
    forbid_shortener('vonq.io'),
    forbid_shortener('vrnda.us'),
    forbid_shortener('vtns.io'),
    forbid_shortener('vur.me'),
    forbid_shortener('vurl.com'),
    forbid_shortener('vvnt.co'),
    forbid_shortener('vxn.link'),
    forbid_shortener('vypij.bar'),
    forbid_shortener('vz.to'),
    forbid_shortener('vzturl.com'),
    forbid_shortener('w.idg.de'),
    forbid_shortener('w.wiki'),
    forbid_shortener('w5n.co'),
    forbid_shortener('wa.link'),
    forbid_shortener('wa.me'),
    forbid_shortener('wa.sv'),
    forbid_shortener('waa.ai'),
    forbid_shortener('waad.co'),
    forbid_shortener('wahoowa.net'),
    forbid_shortener('walk.sc'),
    forbid_shortener('walkjc.org'),
    forbid_shortener('wapo.st'),
    forbid_shortener('warby.me'),
    forbid_shortener('warp.plus'),
    forbid_shortener('wartsi.ly'),
    forbid_shortener('way.to'),
    forbid_shortener('wb.md'),
    forbid_shortener('wbby.co'),
    forbid_shortener('wbur.fm'),
    forbid_shortener('wbze.de'),
    forbid_shortener('wcha.it'),
    forbid_shortener('we.co'),
    forbid_shortener('weall.vote'),
    forbid_shortener('weare.rs'),
    forbid_shortener('wee.so'),
    forbid_shortener('wef.ch'),
    forbid_shortener('wellc.me'),
    forbid_shortener('wenk.io'),
    forbid_shortener('wf0.xin'),
    forbid_shortener('whatel.se'),
    forbid_shortener('whcs.law'),
    forbid_shortener('whi.ch'),
    forbid_shortener('whoel.se'),
    forbid_shortener('whr.tn'),
    forbid_shortener('wi.se'),
    forbid_shortener('win.gs'),
    forbid_shortener('wit.to'),
    forbid_shortener('wjcf.co'),
    forbid_shortener('wkf.ms'),
    forbid_shortener('wmojo.com'),
    forbid_shortener('wn.nr'),
    forbid_shortener('wndrfl.co'),
    forbid_shortener('wo.ws'),
    forbid_shortener('wooo.tw'),
    forbid_shortener('wp.me'),
    forbid_shortener('wpbeg.in'),
    forbid_shortener('wrctr.co'),
    forbid_shortener('wrd.cm'),
    forbid_shortener('wrem.it'),
    forbid_shortener('wun.io'),
    forbid_shortener('ww7.fr'),
    forbid_shortener('wwf.to'),
    forbid_shortener('wwp.news'),
    forbid_shortener('www.shrunken.com'),
    forbid_shortener('x.co'),
    forbid_shortener('x.gd'),
    forbid_shortener('xbx.lv'),
    forbid_shortener('xerox.bz'),
    forbid_shortener('xfin.tv'),
    forbid_shortener('xfl.ag'),
    forbid_shortener('xfru.it'),
    forbid_shortener('xgam.es'),
    forbid_shortener('xor.tw'),
    forbid_shortener('xpr.li'),
    forbid_shortener('xprt.re'),
    forbid_shortener('xqss.org'),
    forbid_shortener('xrds.ca'),
    forbid_shortener('xrl.us'),
    forbid_shortener('xurl.es'),
    forbid_shortener('xvirt.it'),
    forbid_shortener('y.ahoo.it'),
    forbid_shortener('y2u.be'),
    forbid_shortener('yadi.sk'),
    forbid_shortener('yal.su'),
    forbid_shortener('yelp.to'),
    forbid_shortener('yex.tt'),
    forbid_shortener('yhoo.it'),
    forbid_shortener('yip.su'),
    forbid_shortener('yji.tw'),
    forbid_shortener('ynews.page.link'),
    forbid_shortener('yoox.ly'),
    forbid_shortener('your.ls'),
    forbid_shortener('yourls.org'),
    forbid_shortener('yourwish.es'),
    forbid_shortener('youtu.be'),
    forbid_shortener('yubi.co'),
    forbid_shortener('yun.ir'),
    forbid_shortener('z23.ru'),
    forbid_shortener('zaya.io'),
    forbid_shortener('zc.vg'),
    forbid_shortener('zcu.io'),
    forbid_shortener('zd.net'),
    forbid_shortener('zdrive.li'),
    forbid_shortener('zdsk.co'),
    forbid_shortener('zecz.ec'),
    forbid_shortener('zeep.ly'),
    forbid_shortener('zez.kr'),
    forbid_shortener('zi.ma'),
    forbid_shortener('ziadi.co'),
    forbid_shortener('zip.net'),
    forbid_shortener('zipurl.fr'),
    forbid_shortener('zln.do'),
    forbid_shortener('zlr.my'),
    forbid_shortener('zlra.co'),
    forbid_shortener('zlw.re'),
    forbid_shortener('zoho.to'),
    forbid_shortener('zopen.to'),
    forbid_shortener('zovpart.com'),
    forbid_shortener('zpr.io'),
    forbid_shortener('zuki.ie'),
    forbid_shortener('zuplo.link'),
    forbid_shortener('zurb.us'),
    forbid_shortener('zurins.uk'),
    forbid_shortener('zurl.co'),
    forbid_shortener('zurl.ir'),
    forbid_shortener('zurl.ws'),
    forbid_shortener('zws.im'),
    forbid_shortener('zxc.li'),
    forbid_shortener('zynga.my'),
    forbid_shortener('zywv.us'),
    forbid_shortener('zzb.bz'),
    forbid_shortener('zzu.info'),
    forbid_shortener('✩.ws'),
    forbid_shortener('➡.ws'),
]

HTTP_CHECKS = (
    HTTPS_ENFORCINGS
    + HTTP_URL_SHORTENERS
    + [
        (
            re.compile(r'^(?!https?://)[^/]+'),
            _("URL must start with https:// or http://"),
        ),
        (
            re.compile(r'^https://(github|gitlab)\.com(/[^/]+){2,3}\.git'),
            _("Appending .git is not necessary"),
        ),
    ]
)

REQUIRE_HTTPS = [
    (
        re.compile(r'^(?!https://)[^/]+'),
        _("URL must start with https://"),
    )
]

REGEX_CHECKS = {
    'Binaries': HTTP_URL_SHORTENERS + REQUIRE_HTTPS,
    'WebSite': HTTP_CHECKS,
    'SourceCode': HTTP_CHECKS,
    'UpdateCheckMode': HTTPS_ENFORCINGS,
    'IssueTracker': HTTP_CHECKS
    + [
        (re.compile(r'.*github\.com/[^/]+/[^/]+/*$'), _("/issues is missing")),
        (re.compile(r'.*gitlab\.com/[^/]+/[^/]+/*$'), _("/issues is missing")),
    ],
    'Donate': HTTP_URL_SHORTENERS
    + REQUIRE_HTTPS
    + [
        (
            re.compile(r'.*liberapay\.com'),
            _("Liberapay donation methods belong in the Liberapay: field"),
        ),
        (
            re.compile(r'.*opencollective\.com'),
            _("OpenCollective donation methods belong in the OpenCollective: field"),
        ),
    ],
    'Changelog': HTTP_CHECKS,
    'Summary': [
        (
            re.compile(r'.*\b(free software|open source)\b.*', re.IGNORECASE),
            _("No need to specify that the app is Free Software"),
        ),
        (
            re.compile(
                r'.*((your|for).*android|android.*(app|device|client|port|version))',
                re.IGNORECASE,
            ),
            _("No need to specify that the app is for Android"),
        ),
        (re.compile(r'.*[a-z0-9][.!?]( |$)'), _("Punctuation should be avoided")),
    ],
    'Description': HTTPS_ENFORCINGS
    + HTTP_URL_SHORTENERS
    + [
        (
            re.compile(r'https://f-droid.org/[a-z][a-z](_[A-Za-z]{2,4})?/'),
            _("Locale included in f-droid.org URL"),
        ),
        (
            re.compile(
                r'.*<(applet|base|body|button|embed|form|head|html|iframe|img|input|link|object|picture|script|source|style|svg|video).*',
                re.IGNORECASE,
            ),
            _("Forbidden HTML tags"),
        ),
        (
            re.compile(r""".*\s+src=["']javascript:.*"""),
            _("Javascript in HTML src attributes"),
        ),
    ],
}

# config keys that are currently ignored by lint, but could be supported.
IGNORE_CONFIG_KEYS = (
    'github_releases',
    'java_paths',
)

BOOL_KEYS = (
    'allow_disabled_algorithms',
    'androidobservatory',
    'build_server_always',
    'deploy_process_logs',
    'keep_when_not_allowed',
    'make_current_version_link',
    'nonstandardwebroot',
    'per_app_repos',
    'refresh_scanner',
    'scan_binary',
    'sync_from_local_copy_dir',
)

CHECK_CONFIG_KEYS = (
    'ant',
    'apk_signing_key_block_list',
    'archive',
    'archive_description',
    'archive_icon',
    'archive_name',
    'archive_older',
    'archive_url',
    'archive_web_base_url',
    'awsbucket',
    'awsbucket_index_only',
    'binary_transparency_remote',
    'cachedir',
    'char_limits',
    'current_version_name_source',
    'git_mirror_size_limit',
    'github_token',
    'gpghome',
    'gpgkey',
    'gradle',
    'identity_file',
    'install_list',
    'java_paths',
    'keyaliases',
    'keydname',
    'keypass',
    'keystore',
    'keystorepass',
    'lint_licenses',
    'local_copy_dir',
    'mirrors',
    'mvn3',
    'ndk_paths',
    'path_to_custom_rclone_config',
    'rclone_config',
    'repo',
    'repo_description',
    'repo_icon',
    'repo_key_sha256',
    'repo_keyalias',
    'repo_maxage',
    'repo_name',
    'repo_pubkey',
    'repo_url',
    'repo_web_base_url',
    'scanner_signature_sources',
    'sdk_path',
    'servergitmirrors',
    'serverwebroot',
    'smartcardoptions',
    'sync_from_local_copy_dir',
    'uninstall_list',
    'virustotal_apikey',
)

LOCALE_PATTERN = re.compile(r"[a-z]{2,3}(-([A-Z][a-zA-Z]+|\d+|[a-z]+))*")

VERSIONCODE_CHECK_PATTERN = re.compile(r"(\\d|\[(0-9|\\d)_?(a-fA-F)?])[+]")

ANTIFEATURES_KEYS = None
ANTIFEATURES_PATTERN = None
CATEGORIES_KEYS = list()


def load_antiFeatures_config():
    """Lazy loading, since it might read a lot of files."""
    global ANTIFEATURES_KEYS, ANTIFEATURES_PATTERN
    k = common.ANTIFEATURES_CONFIG_NAME
    if not ANTIFEATURES_KEYS or k not in common.config:
        common.config[k] = common.load_localized_config(k, 'repo')
        ANTIFEATURES_KEYS = sorted(common.config[k].keys())
        ANTIFEATURES_PATTERN = ','.join(ANTIFEATURES_KEYS)


def load_categories_config():
    """Lazy loading, since it might read a lot of files."""
    global CATEGORIES_KEYS
    k = common.CATEGORIES_CONFIG_NAME
    if not CATEGORIES_KEYS:
        if common.config and k in common.config:
            CATEGORIES_KEYS = common.config[k]
        else:
            common.config[k] = common.load_localized_config(k, 'repo')
            CATEGORIES_KEYS = list(common.config[k].keys())


def check_regexes(app):
    for f, checks in REGEX_CHECKS.items():
        for m, r in checks:
            v = app.get(f)
            t = metadata.fieldtype(f)
            if t == metadata.TYPE_MULTILINE:
                for line in v.splitlines():
                    if m.match(line):
                        yield "%s at line '%s': %s" % (f, line, r)
            else:
                if v is None:
                    continue
                if m.match(v):
                    yield "%s '%s': %s" % (f, v, r)


def get_lastbuild(builds):
    lowest_vercode = -1
    lastbuild = None
    for build in builds:
        if not build.disable:
            vercode = build.versionCode
            if lowest_vercode == -1 or vercode < lowest_vercode:
                lowest_vercode = vercode
        if not lastbuild or build.versionCode > lastbuild.versionCode:
            lastbuild = build
    return lastbuild


def check_update_check_data_url(app):  # noqa: D403
    """UpdateCheckData must have a valid HTTPS URL to protect checkupdates runs."""
    if app.UpdateCheckData and app.UpdateCheckMode == 'HTTP':
        urlcode, codeex, urlver, verex = app.UpdateCheckData.split('|')
        for url in (urlcode, urlver):
            if url != '.':
                parsed = urllib.parse.urlparse(url)
                if not parsed.scheme or not parsed.netloc:
                    yield _('UpdateCheckData not a valid URL: {url}').format(url=url)
                if parsed.scheme != 'https':
                    yield _('UpdateCheckData must use HTTPS URL: {url}').format(url=url)


def check_update_check_data_int(app):  # noqa: D403
    """UpdateCheckData regex must match integers."""
    if app.UpdateCheckData:
        urlcode, codeex, urlver, verex = app.UpdateCheckData.split('|')
        # codeex can be empty as well
        if codeex and not VERSIONCODE_CHECK_PATTERN.search(codeex):
            yield _(
                f'UpdateCheckData must match the versionCode as integer (\\d or [0-9]): {codeex}'
            )


def check_vercode_operation(app):
    if not app.VercodeOperation:
        return
    invalid_ops = []
    for op in app.VercodeOperation:
        if not common.VERCODE_OPERATION_RE.match(op):
            invalid_ops += op
    if invalid_ops:
        yield _('Invalid VercodeOperation: {invalid_ops}').format(
            invalid_ops=invalid_ops
        )


def check_ucm_tags(app):
    lastbuild = get_lastbuild(app.get('Builds', []))
    if (
        lastbuild is not None
        and lastbuild.commit
        and app.UpdateCheckMode == 'RepoManifest'
        and not lastbuild.commit.startswith('unknown')
        and lastbuild.versionCode == app.CurrentVersionCode
        and not lastbuild.forcevercode
        and any(s in lastbuild.commit for s in '.,_-/')
    ):
        yield _(
            "Last used commit '{commit}' looks like a tag, but UpdateCheckMode is '{ucm}'"
        ).format(commit=lastbuild.commit, ucm=app.UpdateCheckMode)


def check_char_limits(app):
    limits = common.config['char_limits']

    if len(app.Summary) > limits['summary']:
        yield _("Summary of length {length} is over the {limit} char limit").format(
            length=len(app.Summary), limit=limits['summary']
        )

    if len(app.Description) > limits['description']:
        yield _("Description of length {length} is over the {limit} char limit").format(
            length=len(app.Description), limit=limits['description']
        )


def check_old_links(app):
    usual_sites = [
        'github.com',
        'gitlab.com',
        'bitbucket.org',
    ]
    old_sites = [
        'gitorious.org',
        'code.google.com',
    ]
    if any(s in app.Repo for s in usual_sites):
        for f in ['WebSite', 'SourceCode', 'IssueTracker', 'Changelog']:
            v = app.get(f)
            if any(s in v for s in old_sites):
                yield _("App is in '{repo}' but has a link to {url}").format(
                    repo=app.Repo, url=v
                )


def check_useless_fields(app):
    if app.UpdateCheckName == app.id:
        yield _("UpdateCheckName is set to the known application ID, it can be removed")


FILLING_UCMS = re.compile(r'^(Tags.*|RepoManifest.*)')


def check_checkupdates_ran(app):
    if FILLING_UCMS.match(app.UpdateCheckMode):
        if not app.AutoName and not app.CurrentVersion and app.CurrentVersionCode == 0:
            yield _(
                "UpdateCheckMode is set but it looks like checkupdates hasn't been run yet."
            )


def check_empty_fields(app):
    if not app.Categories:
        yield _("Categories are not set")


def check_categories(app):
    """App uses 'Categories' key and parsed config uses 'categories' key."""
    for categ in app.Categories:
        if categ not in CATEGORIES_KEYS:
            yield _("Categories '%s' is not valid" % categ)


def check_duplicates(app):
    links_seen = set()
    for f in ['Source Code', 'Web Site', 'Issue Tracker', 'Changelog']:
        v = app.get(f)
        if not v:
            continue
        v = v.lower()
        if v in links_seen:
            yield _("Duplicate link in '{field}': {url}").format(field=f, url=v)
        else:
            links_seen.add(v)

    name = common.get_app_display_name(app)
    if app.Summary and name:
        if app.Summary.lower() == name.lower():
            yield _("Summary '%s' is just the app's name") % app.Summary

    if app.Summary and app.Description and len(app.Description) == 1:
        if app.Summary.lower() == app.Description[0].lower():
            yield _("Description '%s' is just the app's summary") % app.Summary

    seenlines = set()
    for line in app.Description.splitlines():
        if len(line) < 1:
            continue
        if line in seenlines:
            yield _("Description has a duplicate line")
        seenlines.add(line)


def check_builds(app):
    supported_flags = set(metadata.build_flags)
    binaries_url = app.get('Binaries')
    for build in app.get('Builds', []):
        if build.disable:
            if build.disable.startswith('Generated by import.py'):
                yield _(
                    "Build generated by `fdroid import` - remove disable line once ready"
                )
            continue
        has_binaries = bool(binaries_url or build.get('binary'))
        for s in ['master', 'main', 'origin', 'HEAD', 'default', 'develop', 'trunk']:
            if build.commit and build.commit.startswith(s):
                yield _(
                    "Branch '{branch}' used as commit in build '{versionName}'"
                ).format(branch=s, versionName=build.versionName)
            for srclib in build.srclibs:
                if '@' in srclib:
                    ref = srclib.split('@')[1].split('/')[0]
                    if ref.startswith(s) and has_binaries:
                        yield _(
                            "Branch '{branch}' used as commit in srclib '{srclib}'"
                        ).format(branch=s, srclib=srclib)
                else:
                    yield (
                        _('srclibs missing name and/or @')
                        + ' (srclibs: '
                        + srclib
                        + ')'
                    )
        for key in build.keys():
            if key not in supported_flags:
                yield _('%s is not an accepted build field') % key
        v = build.get('binary')
        if v:
            for m, r in HTTP_URL_SHORTENERS + REQUIRE_HTTPS:
                if m.match(v):
                    yield f":{build.versionCode} 'binary: {v}' {r}"


def check_files_dir(app):
    dir_path = Path('metadata') / app.id
    if not dir_path.is_dir():
        return
    files = set()
    for path in dir_path.iterdir():
        name = path.name
        if not (
            path.is_file() or name == 'signatures' or LOCALE_PATTERN.fullmatch(name)
        ):
            yield _("Found non-file at %s") % path
            continue
        files.add(name)

    used = {
        'signatures',
    }
    for build in app.get('Builds', []):
        for fname in build.patch:
            if fname not in files:
                yield _("Unknown file '{filename}' in build '{versionName}'").format(
                    filename=fname, versionName=build.versionName
                )
            else:
                used.add(fname)

    for name in files.difference(used):
        if LOCALE_PATTERN.fullmatch(name):
            continue
        yield _("Unused file at %s") % (dir_path / name)


def check_license_tag(app):
    """Ensure all license tags contain only valid/approved values.

    It is possible to disable license checking by setting a null or empty value,
    e.g. `lint_licenses: ` or `lint_licenses: []`

    """
    if 'lint_licenses' in common.config:
        lint_licenses = common.config['lint_licenses']
        if lint_licenses is None:
            return
    else:
        lint_licenses = APPROVED_LICENSES
    if app.License not in lint_licenses:
        if lint_licenses == APPROVED_LICENSES:
            yield _(
                'Unexpected license tag "{}"! Only use FSF or OSI '
                'approved tags from https://spdx.org/license-list'
            ).format(app.License)
        else:
            yield _(
                'Unexpected license tag "{}"! Only use license tags '
                'configured in your config file'
            ).format(app.License)


def check_extlib_dir(apps):
    dir_path = Path('build/extlib')
    extlib_files = set()
    for path in dir_path.glob('**/*'):
        if path.is_file():
            extlib_files.add(path.relative_to(dir_path))

    used = set()
    for app in apps:
        if app.Disabled:
            continue
        archive_policy = common.calculate_archive_policy(
            app, common.config['archive_older']
        )
        builds = [build for build in app.Builds if not build.disable]

        for i in range(len(builds)):
            build = builds[i]
            for path in build.extlibs:
                path = Path(path)
                if path not in extlib_files:
                    # Don't show error on archived versions
                    if i >= len(builds) - archive_policy:
                        yield _(
                            "{appid}: Unknown extlib {path} in build '{versionName}'"
                        ).format(appid=app.id, path=path, versionName=build.versionName)
                else:
                    used.add(path)

    for path in extlib_files.difference(used):
        if path.name not in [
            '.gitignore',
            'source.txt',
            'origin.txt',
            'md5.txt',
            'LICENSE',
            'LICENSE.txt',
            'COPYING',
            'COPYING.txt',
            'NOTICE',
            'NOTICE.txt',
        ]:
            yield _("Unused extlib at %s") % (dir_path / path)


def check_app_field_types(app):
    """Check the fields have valid data types."""
    for field in app.keys():
        v = app.get(field)
        t = metadata.fieldtype(field)
        if v is None:
            continue
        elif field == 'Builds':
            if not isinstance(v, list):
                yield (
                    _(
                        "{appid}: {field} must be a '{type}', but it is a '{fieldtype}'!"
                    ).format(
                        appid=app.id,
                        field=field,
                        type='list',
                        fieldtype=v.__class__.__name__,
                    )
                )
        elif t == metadata.TYPE_LIST and not isinstance(v, list):
            yield (
                _(
                    "{appid}: {field} must be a '{type}', but it is a '{fieldtype}!'"
                ).format(
                    appid=app.id,
                    field=field,
                    type='list',
                    fieldtype=v.__class__.__name__,
                )
            )
        elif t == metadata.TYPE_STRING and type(v) not in (str, bool, dict):
            yield (
                _(
                    "{appid}: {field} must be a '{type}', but it is a '{fieldtype}'!"
                ).format(
                    appid=app.id,
                    field=field,
                    type='str',
                    fieldtype=v.__class__.__name__,
                )
            )
        elif t == metadata.TYPE_STRINGMAP and not isinstance(v, dict):
            yield (
                _(
                    "{appid}: {field} must be a '{type}', but it is a '{fieldtype}'!"
                ).format(
                    appid=app.id,
                    field=field,
                    type='dict',
                    fieldtype=v.__class__.__name__,
                )
            )
        elif t == metadata.TYPE_INT and not isinstance(v, int):
            yield (
                _(
                    "{appid}: {field} must be a '{type}', but it is a '{fieldtype}'!"
                ).format(
                    appid=app.id,
                    field=field,
                    type='int',
                    fieldtype=v.__class__.__name__,
                )
            )


def check_antiFeatures(app):
    """Check the Anti-Features keys match those declared in the config."""
    pattern = ANTIFEATURES_PATTERN
    msg = _("'{value}' is not a valid {field} in {appid}. Regex pattern: {pattern}")

    field = 'AntiFeatures'  # App entries use capitalized CamelCase
    for value in app.get(field, []):
        if value not in ANTIFEATURES_KEYS:
            yield msg.format(value=value, field=field, appid=app.id, pattern=pattern)

    field = 'antifeatures'  # Build entries use all lowercase
    for build in app.get('Builds', []):
        build_antiFeatures = build.get(field, [])
        for value in build_antiFeatures:
            if value not in ANTIFEATURES_KEYS:
                yield msg.format(
                    value=value, field=field, appid=app.id, pattern=pattern
                )


def check_for_unsupported_metadata_files(basedir=""):
    """Check whether any non-metadata files are in metadata/."""
    basedir = Path(basedir)

    if not (basedir / 'metadata').exists():
        return False
    return_value = False
    for f in (basedir / 'metadata').iterdir():
        if f.is_dir():
            if not Path(str(f) + '.yml').exists():
                print(_('"%s/" has no matching metadata file!') % f)
                return_value = True
        elif f.suffix == '.yml':
            packageName = f.stem
            if not common.is_valid_package_name(packageName):
                print(
                    '"'
                    + packageName
                    + '" is an invalid package name!\n'
                    + 'https://developer.android.com/studio/build/application-id'
                )
                return_value = True
        else:
            print(
                _(
                    '"{path}" is not a supported file format (use: metadata/*.yml)'
                ).format(path=f.relative_to(basedir))
            )
            return_value = True

    return return_value


def check_current_version_code(app):
    """Check that the CurrentVersionCode is currently available."""
    if app.get('ArchivePolicy') == 0:
        return
    cv = app.get('CurrentVersionCode')
    if cv is not None and cv == 0:
        return

    builds = app.get('Builds')
    active_builds = 0
    min_versionCode = None
    if builds:
        for build in builds:
            vc = build['versionCode']
            if min_versionCode is None or min_versionCode > vc:
                min_versionCode = vc
            if not build.get('disable'):
                active_builds += 1
            if cv == build['versionCode']:
                break
    if active_builds == 0:
        return  # all builds are disabled
    if cv is not None and cv < min_versionCode:
        yield (
            _(
                'CurrentVersionCode {cv} is less than oldest build entry {versionCode}'
            ).format(cv=cv, versionCode=min_versionCode)
        )


def check_updates_expected(app):
    """Check if update checking makes sense."""
    if (app.get('NoSourceSince') or app.get('ArchivePolicy') == 0) and not all(
        app.get(key, 'None') == 'None' for key in ('AutoUpdateMode', 'UpdateCheckMode')
    ):
        yield _(
            'App has NoSourceSince or ArchivePolicy "0 versions" or 0 but AutoUpdateMode or UpdateCheckMode are not None'
        )


def check_updates_ucm_http_aum_pattern(app):  # noqa: D403
    """AutoUpdateMode with UpdateCheckMode: HTTP must have a pattern."""
    if app.UpdateCheckMode == "HTTP" and app.AutoUpdateMode == "Version":
        yield _("AutoUpdateMode with UpdateCheckMode: HTTP must have a pattern.")


def check_certificate_pinned_binaries(app):
    keys = app.get('AllowedAPKSigningKeys')
    known_keys = common.config.get('apk_signing_key_block_list', [])
    if keys:
        if known_keys:
            for key in keys:
                if key in known_keys:
                    yield _('Known debug key is used in AllowedAPKSigningKeys: ') + key
        return
    if app.get('Binaries') is not None:
        yield _(
            'App has Binaries but does not have corresponding AllowedAPKSigningKeys to pin certificate.'
        )
        return
    builds = app.get('Builds')
    if builds is None:
        return
    for build in builds:
        if build.get('binary') is not None:
            yield _(
                'App version has binary but does not have corresponding AllowedAPKSigningKeys to pin certificate.'
            )
            return


REPO_GIT_URL = re.compile(r'^https://.*')
REPO_SRCLIB_URL = re.compile(r'^[^/@]+$')


def check_repo(app):
    """Check Repo: has acceptable URLs."""
    repo = app['Repo']
    if app['RepoType'] == 'git' and not REPO_GIT_URL.match(repo):
        yield _('Repo: git URLs must use https://')
    if app['RepoType'] == 'srclib':
        m = REPO_SRCLIB_URL.match(repo)
        if not m:
            yield _('Repo: srclib URLs must be only a srclib name, not a path or URL.')
        srclib = f'srclibs/{repo}.yml'
        if not Path(srclib).exists():
            yield _('Repo: srclib URLs must be the name of an existing srclib!')


def lint_config(arg):
    path = Path(arg)
    passed = True

    mirrors_name = f'{common.MIRRORS_CONFIG_NAME}.yml'
    config_name = f'{common.CONFIG_CONFIG_NAME}.yml'
    categories_name = f'{common.CATEGORIES_CONFIG_NAME}.yml'
    antifeatures_name = f'{common.ANTIFEATURES_CONFIG_NAME}.yml'

    yamllintresult = common.run_yamllint(path)
    if yamllintresult:
        print(yamllintresult)
        passed = False

    with path.open() as fp:
        data = yaml.load(fp)
    common.config_type_check(arg, data)

    if path.name == mirrors_name:
        import pycountry

        valid_country_codes = [c.alpha_2 for c in pycountry.countries]
        for mirror in data:
            code = mirror.get('countryCode')
            if code and code not in valid_country_codes:
                passed = False
                msg = _(
                    '{path}: "{code}" is not a valid ISO_3166-1 alpha-2 country code!'
                ).format(path=str(path), code=code)
                if code.upper() in valid_country_codes:
                    m = [code.upper()]
                else:
                    m = difflib.get_close_matches(
                        code.upper(), valid_country_codes, 2, 0.5
                    )
                if m:
                    msg += ' '
                    msg += _('Did you mean {code}?').format(code=', '.join(sorted(m)))
                print(msg)
    elif path.name == config_name and path.parent.name != 'config':
        valid_keys = set(tuple(common.default_config) + BOOL_KEYS + CHECK_CONFIG_KEYS)
        for key in IGNORE_CONFIG_KEYS:
            if key in valid_keys:
                valid_keys.remove(key)
        for key in data:
            if key not in valid_keys:
                passed = False
                msg = _("ERROR: {key} not a valid key!").format(key=key)
                m = difflib.get_close_matches(key.lower(), valid_keys, 2, 0.5)
                if m:
                    msg += ' '
                    msg += _('Did you mean {code}?').format(code=', '.join(sorted(m)))
                print(msg)
                continue

            if key in BOOL_KEYS:
                t = bool
            else:
                t = type(common.default_config.get(key, ""))

            show_error = False
            if t is str:
                if type(data[key]) not in (str, list, dict):
                    passed = False
                    show_error = True
            elif type(data[key]) != t:
                passed = False
                show_error = True
            if show_error:
                print(
                    _("ERROR: {key}'s value should be of type {t}!").format(
                        key=key, t=t.__name__
                    )
                )
    elif path.name in (config_name, categories_name, antifeatures_name):
        for key in data:
            if path.name == config_name and key not in ('archive', 'repo'):
                passed = False
                print(
                    _('ERROR: {key} in {path} is not "archive" or "repo"!').format(
                        key=key, path=path
                    )
                )
            allowed_keys = ['name']
            if path.name in [config_name, antifeatures_name]:
                allowed_keys.append('description')
            # only for source strings currently
            if path.parent.name == 'config':
                allowed_keys.append('icon')
            for subkey in data[key]:
                if subkey not in allowed_keys:
                    passed = False
                    print(
                        _(
                            'ERROR: {key}:{subkey} in {path} is not in allowed keys: {allowed_keys}!'
                        ).format(
                            key=key,
                            subkey=subkey,
                            path=path,
                            allowed_keys=', '.join(allowed_keys),
                        )
                    )

    return passed


def main():
    parser = ArgumentParser()
    common.setup_global_opts(parser)
    parser.add_argument(
        "-f",
        "--format",
        action="store_true",
        default=False,
        help=_("Also warn about formatting issues, like rewritemeta -l"),
    )
    parser.add_argument(
        '--force-yamllint',
        action="store_true",
        default=False,
        help=_(
            "When linting the entire repository yamllint is disabled by default. "
            "This option forces yamllint regardless."
        ),
    )
    parser.add_argument(
        "appid", nargs='*', help=_("application ID of file to operate on")
    )
    metadata.add_metadata_arguments(parser)
    options = common.parse_args(parser)
    metadata.warnings_action = options.W

    common.get_config()
    load_antiFeatures_config()
    load_categories_config()

    if options.force_yamllint:
        import yamllint  # throw error if it is not installed

        yamllint  # make pyflakes ignore this

    paths = list()
    for arg in options.appid:
        if (
            arg == common.CONFIG_FILE
            or Path(arg).parent.name == 'config'
            or Path(arg).parent.parent.name == 'config'  # localized
        ):
            paths.append(arg)

    failed = 0
    if paths:
        for path in paths:
            options.appid.remove(path)
            if not lint_config(path):
                failed += 1
        # an empty list of appids means check all apps, avoid that if files were given
        if not options.appid:
            sys.exit(failed)

    if not lint_metadata(options):
        failed += 1

    if failed:
        sys.exit(failed)


def lint_metadata(options):
    apps = common.read_app_args(options.appid)

    anywarns = check_for_unsupported_metadata_files()

    apps_check_funcs = []
    if not options.appid:
        # otherwise it finds tons of unused extlibs
        apps_check_funcs.append(check_extlib_dir)
    for check_func in apps_check_funcs:
        for warn in check_func(apps.values()):
            anywarns = True
            print(warn)

    for appid, app in apps.items():
        if app.Disabled:
            continue

        # only run yamllint when linting individual apps.
        if options.appid or options.force_yamllint:
            # run yamllint on app metadata
            ymlpath = Path('metadata') / (appid + '.yml')
            if ymlpath.is_file():
                yamllintresult = common.run_yamllint(ymlpath)
                if yamllintresult:
                    print(yamllintresult)

            # run yamllint on srclib metadata
            srclibs = set()
            for build in app.get('Builds', []):
                for srclib in build.srclibs:
                    name, _ref, _number, _subdir = common.parse_srclib_spec(srclib)
                    srclibs.add(name + '.yml')
            for srclib in srclibs:
                srclibpath = Path('srclibs') / srclib
                if srclibpath.is_file():
                    if platform.system() == 'Windows':
                        # Handle symlink on Windows
                        symlink = srclibpath.read_text()
                        if symlink in srclibs:
                            continue
                        elif (srclibpath.parent / symlink).is_file():
                            srclibpath = srclibpath.parent / symlink
                    yamllintresult = common.run_yamllint(srclibpath)
                    if yamllintresult:
                        print(yamllintresult)

        app_check_funcs = [
            check_app_field_types,
            check_antiFeatures,
            check_regexes,
            check_update_check_data_url,
            check_update_check_data_int,
            check_vercode_operation,
            check_ucm_tags,
            check_char_limits,
            check_old_links,
            check_checkupdates_ran,
            check_useless_fields,
            check_empty_fields,
            check_categories,
            check_duplicates,
            check_builds,
            check_files_dir,
            check_license_tag,
            check_current_version_code,
            check_updates_expected,
            check_updates_ucm_http_aum_pattern,
            check_certificate_pinned_binaries,
            check_repo,
        ]

        for check_func in app_check_funcs:
            for warn in check_func(app):
                anywarns = True
                print("%s: %s" % (appid, warn))

        if options.format and not rewritemeta.proper_format(app):
            print("%s: %s" % (appid, _("Run rewritemeta to fix formatting")))
            anywarns = True

    return not anywarns


# A compiled, public domain list of official SPDX license tags.  generated
# using: `python3 -m spdx_license_list print --filter-fsf-or-osi` Only contains
# licenes approved by either FSF to be free/libre software or OSI to be open
# source
APPROVED_LICENSES = [
    '0BSD',
    'AAL',
    'AFL-1.1',
    'AFL-1.2',
    'AFL-2.0',
    'AFL-2.1',
    'AFL-3.0',
    'AGPL-3.0-only',
    'AGPL-3.0-or-later',
    'APL-1.0',
    'APSL-1.0',
    'APSL-1.1',
    'APSL-1.2',
    'APSL-2.0',
    'Apache-1.0',
    'Apache-1.1',
    'Apache-2.0',
    'Artistic-1.0',
    'Artistic-1.0-Perl',
    'Artistic-1.0-cl8',
    'Artistic-2.0',
    'BSD-1-Clause',
    'BSD-2-Clause',
    'BSD-2-Clause-Patent',
    'BSD-3-Clause',
    'BSD-3-Clause-Clear',
    'BSD-3-Clause-LBNL',
    'BSD-4-Clause',
    'BSL-1.0',
    'BitTorrent-1.1',
    'CAL-1.0',
    'CAL-1.0-Combined-Work-Exception',
    'CATOSL-1.1',
    'CC-BY-4.0',
    'CC-BY-SA-4.0',
    'CC0-1.0',
    'CDDL-1.0',
    'CECILL-2.0',
    'CECILL-2.1',
    'CECILL-B',
    'CECILL-C',
    'CNRI-Python',
    'CPAL-1.0',
    'CPL-1.0',
    'CUA-OPL-1.0',
    'ClArtistic',
    'Condor-1.1',
    'ECL-1.0',
    'ECL-2.0',
    'EFL-1.0',
    'EFL-2.0',
    'EPL-1.0',
    'EPL-2.0',
    'EUDatagrid',
    'EUPL-1.1',
    'EUPL-1.2',
    'Entessa',
    'FSFAP',
    'FTL',
    'Fair',
    'Frameworx-1.0',
    'GFDL-1.1-only',
    'GFDL-1.1-or-later',
    'GFDL-1.2-only',
    'GFDL-1.2-or-later',
    'GFDL-1.3-only',
    'GFDL-1.3-or-later',
    'GPL-2.0-only',
    'GPL-2.0-or-later',
    'GPL-3.0-only',
    'GPL-3.0-or-later',
    'HPND',
    'IJG',
    'IPA',
    'IPL-1.0',
    'ISC',
    'Imlib2',
    'Intel',
    'LGPL-2.0-only',
    'LGPL-2.0-or-later',
    'LGPL-2.1-only',
    'LGPL-2.1-or-later',
    'LGPL-3.0-only',
    'LGPL-3.0-or-later',
    'LPL-1.0',
    'LPL-1.02',
    'LPPL-1.2',
    'LPPL-1.3a',
    'LPPL-1.3c',
    'LiLiQ-P-1.1',
    'LiLiQ-R-1.1',
    'LiLiQ-Rplus-1.1',
    'MIT',
    'MIT-0',
    'MPL-1.0',
    'MPL-1.1',
    'MPL-2.0',
    'MPL-2.0-no-copyleft-exception',
    'MS-PL',
    'MS-RL',
    'MirOS',
    'Motosoto',
    'MulanPSL-2.0',
    'Multics',
    'NASA-1.3',
    'NCSA',
    'NGPL',
    'NOSL',
    'NPL-1.0',
    'NPL-1.1',
    'NPOSL-3.0',
    'NTP',
    'Naumen',
    'Nokia',
    'OCLC-2.0',
    'ODbL-1.0',
    'OFL-1.0',
    'OFL-1.1',
    'OFL-1.1-RFN',
    'OFL-1.1-no-RFN',
    'OGTSL',
    'OLDAP-2.3',
    'OLDAP-2.7',
    'OLDAP-2.8',
    'OSET-PL-2.1',
    'OSL-1.0',
    'OSL-1.1',
    'OSL-2.0',
    'OSL-2.1',
    'OSL-3.0',
    'OpenSSL',
    'PHP-3.0',
    'PHP-3.01',
    'PostgreSQL',
    'Python-2.0',
    'QPL-1.0',
    'RPL-1.1',
    'RPL-1.5',
    'RPSL-1.0',
    'RSCPL',
    'Ruby',
    'SGI-B-2.0',
    'SISSL',
    'SMLNJ',
    'SPL-1.0',
    'SimPL-2.0',
    'Sleepycat',
    'UCL-1.0',
    'UPL-1.0',
    'Unicode-DFS-2016',
    'Unlicense',
    'VSL-1.0',
    'Vim',
    'W3C',
    'WTFPL',
    'Watcom-1.0',
    'X11',
    'XFree86-1.1',
    'Xnet',
    'YPL-1.1',
    'ZPL-2.0',
    'ZPL-2.1',
    'Zend-2.0',
    'Zimbra-1.3',
    'Zlib',
    'gnuplot',
    'iMatix',
    'xinetd',
]

# an F-Droid addition, until we can enforce a better option
APPROVED_LICENSES.append("PublicDomain")

if __name__ == "__main__":
    main()
