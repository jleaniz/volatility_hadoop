from flask import (
    render_template, redirect, url_for, Response
)
from app import analytics_engine, logger, main
from forms import UserForm

@main.route("/api/vpn/byUser/<username>")
def vpnJSON(username):
    if username:
        rdd = analytics_engine.getVPNLoginsByUserJSON(username)

        def generate():
            yield '{"%s": [\n' % (username)
            for doc in rdd.collect():
                yield doc + ',\n'
            yield "{}\n]}"

        return Response(generate(), mimetype='application/json')
    else:
        return 'Username unspecified.'


@main.route("/api/vpn/identifyUser/<date>/<remoteip>")
def identifyVPNAPI(date, remoteip):
    if date and remoteip:
        rdd = analytics_engine.identifyVPNUser(remoteip, date)

        def generate():
            yield '{"%s": [\n' % (remoteip)
            for doc in rdd.collect():
                yield doc + ',\n'
            yield "{}\n]}"

        return Response(generate(), mimetype='application/json')
    else:
        return 'Username unspecified.'


@main.route('/vpn/LoginsByUser/google/<username>')
def vpnGoogleFormat(username):
    if username:
        json = analytics_engine.getVPNLoginsByUserGoogle(username)
        logger.info(json)
        return render_template('vpnGC.html', json=json)
    else:
        return 'Username unspecified.'


@main.route("/vpn/user", methods=('GET', 'POST'))
def vpn_user():
    form = UserForm(csrf_enabled=False)
    if form.validate_on_submit():
        return redirect(url_for('main.vpnGoogleFormat', username=form.name.data))
    return render_template("vpn.html", form=form)
