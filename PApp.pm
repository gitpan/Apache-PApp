if (!defined &Apache::PApp::configure) { eval do { local $/; <DATA> }; die $@ if $@ } 1;
__DATA__

#line 3 "(Apache::PApp source)"

=head1 NAME

Apache::PApp - multi-page-state-preserving web applications

=head1 SYNOPSIS

   #   Apache's httpd.conf file
   #   mandatory: activation of Apache::PApp
   PerlModule Apache::PApp

   # configure the perl module
   <Perl>
      search_path Apache::PApp "/root/src/Fluffball/macro";
      search_path Apache::PApp "/root/src/Fluffball";
      configure Apache::PApp (
         cipherkey => "f87a1b96e906bace04c96dbe562af9731957b44e4c282a1658072f0cbe6ba440",
         pappdb    => "DBI:mysql:papp",
         checkdeps => 1,
      );

      # mount an application (here: dbedit.papp)
      mount Apache::PApp (
         location => "/dbedit",
         src => "dbedit.papp"
      );
   </Perl>

=head1 DESCRIPTION

Apache::PApp is a complete solution for developing multi-page web
applications that preserve state I<across> page views. It also tracks user
id's, supports a user access system and provides many utility functions
(html, sql...). You do not need (and should not use) the CGI module.

Advantages:

=over 4

=item * Speed. Apache::PApp isn't much slower than a hand-coded mod_perl
handler, and this is only due to the extra database request to fetch and
restore state, which typically you would do anyway. To the contrary: a
non-trivial Apache::Registry page is much slower than the equivalent
Apache::PApp application.

=item * Embedded Perl. You can freely embed perl into your documents. In
fact, You can do things like these:

   <h1>Names and amounts</h1>
   <:
      my $st = sql_exec "select name, amount from ...",
               [\my($name, $amount];

      while ($st->fetch) {?>
         Name: $name, Amount: $amount<p>
      <:}
   :>
   <hr>

That is, mixing html and perl at statement boundaries.

=item * State-preserving: The global hash C<%state> is automaticaly
preserved during the session. Everything you save there will be available
in any subsequent pages that the user accesses.

=item * XML. PApp-paplications are written in XML. While this is no
advantage in itself, it means that it uses a standardized file format that
can easily be extended. Apache::PApp comes with a DTD and a vim syntax
file, even ;)

=item * Easy internationalization. I18n has never been that easy:
just mark you strings with __"string", either in html or in the perl
source. The "poedit"-demo-application enables editing of the strings
on-line, so translaters need not touch any text files and can work
diretcly via the web.

=item Feature-Rich. Apache::PApp comes with a I<lot> of
small-but-nice-to-have functionality.

=back

Disadvantages:

=over 4

=item * Unfinished Interface: To admit it, this module is a
hack. HMTL::Mason (for example) not only is older and probably larger
and more powerful, it has also a more standardized API. Apache::PApp
will certainly be changed and improved to accomodate new features (like
CGI-only operation).

=item * No documentation. Especially tutorials are missing, so you are
most probably on your own.

=back

Be advised that, IF YOU WANT TO USE THIS MODULE, PELASE DROP THE AUTHOR
(Marc Lehmann <pcg@goof.com>) A MAIL. HE WILL HELP YOU GETTING STARTED.

To get a quick start, read the bench.papp module, the dbedit.papp module,
the cluster.papp module and the papp.dtd description of the papp file
format.

=cut

package Apache::PApp;

use 5.006;

#   imports
use Carp;
use Apache ();
use Apache::Debug;
use Apache::Constants qw(:common);
use FileHandle ();
use File::Basename qw(dirname);

use Storable;
use DBI;
use Apache::PApp;
# Twofish is built-in(!!!)

use subs "fancydie";

BEGIN {
   require DynaLoader;

   $VERSION = 0.1;
   @ISA = qw/Exporter DynaLoader/;
   @EXPORT = qw(
         sql_exec getstate setstate dancydie
         sql_fetch sql_fetchall sql_exists sql_insertid
         errbox debugbox fancydie

         setmsglang gettext N_ __ expand_lang

         surl slink sform cform alink sublink retlink_p returl retlink
         current_locals reference_url mailto_url

         $request $location $module $pmod
         $db %state %param save_prefs $userid
         reload_p switch_userid

         param endform submit textfield password_field textarea escape
         hidden redirect internal_redirect unixtime2http checkbox radio

         dprintf dprint echo capture $request 
         insert_module

   );

   bootstrap Apache::PApp $VERSION;
}

#   globals

$compiled = 1;

my %incpath;  # global search path
my %papp;     # all mounted applications
my $key = pack "H64", "f87a1b96e906bace04c96dbe562af9731957b44e4c282a1658072f0cbe6ba440";
my $cipher_e = new Apache::PApp::Twofish $key;
my $cipher_d = new Apache::PApp::Twofish $key;
my $statedb  = "DBI:mysql:papp";

# can't use my, because of mod_perl's broken-ness :(
my $stateid;     # uncrypted state-id
   $userid;      # uncrypted user-id
   $alternative; # number of alternatives already generated

$NOW;

# other globals. must be globals due to buggy mod_perl
$output;    # the collected output (must be global)
$doutput;   # debugging output
$location;  # the current location (a.k.a. application)
$module;    # the current module(-string)
$pmod;      # the current location (a.k.a. module)
$request;   # the apache request object

$statedbh;  # papp database handle

my $cookie_reset   = 86400;       # reset the cookie at most every ... seconds
my $cookie_expires = 86400 * 365; # cookie expiry time (one year, whooo..)

my $checkdeps; # check dependencies (slow)

my $prevstateid;

$DBD::mysql::QUIET = 1;

=head1 GLOBAL VARIABLES

Some global variables are free to use and even free to change (yes, we
still are about speed, not abstraction).

=over 4

=item $request

The Apache request object (L<Apache>), the  same as returned by C<Apache->request>.

=item %state

A global hash that can be used for almost any purpose, such as saving
state values. All keys with prefix C<papp> are reserved for use by this
module. everything else is yours.

=item $userid

The current userid. User-Id's are automatically assigned to every incoming
connection, you are encouraged to use them for your own user-databases,
but you mustn't trust them.

=item $pmod (a hash-ref)

The current module (don't ask). The only user-accessible keys are:

 lang     a hash-ref enumerating the available langauges, values are
          either language I<Names> or references to another language-id.
 config   the argument to the C<config>option given to  C<mount>.

=item $location

The location value from C<mount>.

=item $module

The current module I<within> the application.
 
=back

=head1 FUNCTIONS/METHODS

=over 4

=item Apache::PApp->search_path(path...);

Add a directory in where to search for included/imported/"module'd" files.

=item Apache::PApp->configure(name => value...);

 pappdb        The (mysql) database to use as papp-database
               (default "DBI:mysql:papp")
 cipherkey*    The Twofish-Key to use (16 binary bytes,)
               BIG SECURITY PROBLEM if not set!
 cookie_reset  delay in seconds after which papp tries to
               re-set the cookie (default: one day)
 cookie_expires time in seconds after which a cookie shall expire
               (default: one year)
 checkdeps     when set, papp will check the .papp file dates for
               every request (slow!!) and will reload the app when necessary.

 [*] required attributes

=item Apache::PApp->mount(location => 'uri', src => 'file.app', ... );

 location[*]   The URI the application is moutned under, must start with "/"
 src[*]        The .papp-file to mount there
 config        Will be available to the module as $pmod->{config]

 [*] required attributes

=cut

sub search_path {
   push @incpath, @_;
}

sub configure {
   my %a = @_;
   $statedb = $a{pappdb} if defined $a{pappdb};
   $cookie_reset = $a{cookie_reset} if defined $a{cookie_reset};
   $cookie_expires = $a{cookie_expires} if defined $a{cookie_expires};
   $checkdeps = $a{checkdeps} if defined $a{checkdeps};
   if (defined $a{cipherkey}) {
      my $key = unpack "H*", $a{cipherkey};
      $ciper_e = new Apache::PApp::Twofish $key;
      $ciper_d = new Apache::PApp::Twofish $key;
   }
}

sub reload_app {
   my ($path, $config) = @_;
   my $pmod = load_papp_file($path);
   $pmod->{config} = $config;
   $pmod->compile;
   $pmod;
}

sub mount {
   my $class = shift;
   my $caller = caller;
   my %args = @_;
   my $location = delete $args{location};
   my $config   = delete $args{config};
   my $src      = delete $args{src};
   my $path = expand_import_path($src);
   $path or die "papp-module '$src' not found\n";
   ${"${caller}::Location"}{$location} = {
         SetHandler  => 'perl-script',
         PerlHandler => 'Apache::PApp::handler',
         %args,
   };
   $papp{$location} = reload_app $path, $config;
}

#############################################################################

=item dprintf "format", value...
dprint value...

Work just like print/printf, except that the output is queued for later use by the C<debugbox> function.

=item echo value[, value...]

Works just like the C<print> function, except that it is faster for generating output.

=item capture { code/macros/html }

Captures the output of "code/macros/perl" and returns it, instead of
sending it to the browser. This is more powerful that it sounds, for
example, this works:

 <:
    my $output = capture {

       print "of course, this is easy\n";
       echo "this as well";
       :>
          
       Yes, this is captured as well!
       <:&this_works:>
       <?$captureme:>

       <:

    }; # close the capture
 :>

=cut

sub echo(@) {
   $output .= join "", @_;
}

sub capture(&) {
   local $output;
   &{$_[0]};
   $output;
}

sub dprintf(@) {
   my $format = shift;
   $doutput .= sprintf $format, @_;
}

sub dprint(@) {
   $doutput .= join "", @_;
}

sub escape($) {
   local $_ = shift;
   s/([()<>%&?, ='"\x00-\x1f\x80-\x9f])/"&#".ord($1).";"/ge;
   $_;
}

=item reference_url $fullurl

Return a url suitable for external referencing of the current
page. If C<$fullurl> is given, a full url (including a protocol
specifier) is generated. Otherwise a partial uri is returned (without
http://host:port/).

This is only a bona-fide attempt: The current module must support starting
a new session and only "import"-variables and input parameters are
preserved.

=cut

sub reference_url {
   my $url;
   if ($_[0]) {
      $url = "http://" . $request->hostname;
      $url .= ":" . $request->get_server_port if $request->get_server_port != 80;
   }
   my $get = join "&", (map {
                escape($_) . (defined $state{$_} ? "=" . escape $state{$_} : "");
             } grep {
                exists $state{$_}
                   and exists $pmod->{state}{import}{$_}
                   and not exists $pmod->{state}{preferences}{$_}
                   and not exists $pmod->{state}{sysprefs}{$_}
             } keys %{$pmod->{state}{import}}),
             (map {
                escape($_) . (defined $param{$_} ? "=" . escape $param{$_} : "");
             } grep {
                exists $state{$_}
                   and not exists $pmod->{state}{import}{$_}
             } keys %param);
   "$url$location/$module" . ($get ? "?$get" : "");
}

=item $ahref = alink contents, url

Create "a link" (a href) with the given contents, pointing at the given url.

=cut

# "link content, url"
sub alink {
   "<a href=\"$_[1]\">$_[0]</a>";
}

=item $url = surl ["module"], arg => value, ...

C<surl> is one of the most often used functions to create urls. The first argument is the name of
a module that the url should refer to. If it is missing the url will refer to the current module.

The remaining arguments are parameters that are passed to the new
module. Unlike GET or POST-requests, these parameters are directly passed
into the C<%state>-hash, i.e. you can use this to alter state values when
the url is activated. This data is transfered in a secure way and can be
quite large (it will not go over the wire).

=cut

sub surl(@) {
   my $module = @_ & 1 ? shift : $module;
   my $location = $module =~ s/^(\/.*?)(?:\/([^\/]*))?$/$2/ ? $1 : $location;

   $alternative++;
   $state{papp}{alternative}[$alternative] = [papp_module => $module, @_];

   "$location/"
      . (unpack "h32", $cipher_e->encrypt(pack "VVVV", $userid, $stateid, $alternative, rand(1<<30)))
      . "/$module";
}

=item $ahref = slink contents,[ module,] arg => value, ...

This is just "alink shift, &url", that is, it returns a link with the
given contants, and a url created by C<surl> (see above). For example, to create
a link to the view_game module for a given game, do this:

 <? slink "Click me to view game #$gamenr", "view_game", gamenr => $gamenr :>

The view_game module can access the game number as $state{gamenr}.

=cut

# complex "link content, secure-args"
sub slink {
   alink shift, &surl;
}

=item $ahref = sublink [sublink-def], content,[ module,] arg => value, ...

=item retlink_p

=item returl

=item retlink

*FIXME*

=cut

# some kind of subroutine call
sub sublink {
   my $chain = shift;
   unshift @$chain, "$location/$module" unless @$chain & 1;
   slink @_, papp_return => [@{$state{papp_return}}, $chain];
}

# is there a backreference?
sub retlink_p() {
   scalar@{$state{papp_return}};
}

sub returl(;@) {
   my @papp_return = @{$state{papp_return}};
   surl @{pop @papp_return}, @_, papp_return => \@papp_return;
}

sub retlink {
   alink shift, &returl;
}

=item %locals = current_locals

Return the current locals (defined as "local" in a state element) as key => value pairs. Useful for sublinks:

 <? sublink [current_locals], "Log me in!", "login" :>

This will create a link to the login-module. In that module, you should provide a link back
to the current page with:

 <? retlink "Return to the caller" :>

=cut

# Return current local variables as key => value pairs.
sub current_locals {
   map { ($_, $state{$_}) }
       grep exists $pmod->{state}{local}{$_}
            && exists $pmod->{state}{local}{$_}{$module},
               keys %state;
}

=item sform [module, ]arg => value, ...

=item cform [module, ]arg => value, ...

=item endform

Return a <form> or </form>-Tag. C<sform> ("simple form") takes the same
arguments as C<surl> and return a <form>-Tag with a GET-Method.  C<cform>
("complex form") does the same, but sets method to POST.

Endform simply returns a closing </form>-Tag, and should be sued to close forms
created via C<sform>/C<cform>.

=cut

sub sform(@) {
   '<form method=GET action="'.&surl.'">';
}

sub cform(@) {
   '<form method=POST action="'.&surl.'">';
}

=item errbox

=item submit

*FIXME*

=cut

sub errbox {
   "<table border=5 width=\"100%\" cellpadding=\"10mm\">"
   ."<tr><td bgcolor=\"#ff0000\"><font color=\"#000000\" size=\"+2\"><b>$_[0]</b></font>"
   ."<tr><td bgcolor=\"#c0c0ff\"><font color=\"#000000\" size=\"+1\"><b><pre>$_[1]</pre></b>&nbsp;</font>"
   ."</table>";
}

sub submit {
   "<input type=submit name=$_[0]".(@_>1 ? " value=\"$_[1]\"" : "").">";
}

sub endform {
   "</form>";
}

sub input_field {
   my $t = shift;
   unshift @_, "name" if @_ & 1;
   my $r = "<$t";
   while (@_) {
      $r .= " ".shift;
      $r .= "=\"".escape($_[0])."\"" if defined $_[0];
      shift;
   }
   $r.">";
}

=item textfield

=item textarea

=item password_field

=item hidden key => value

=item checkbox

=item radio

*FIXME*

=cut

sub password_field	{ input_field "input type=password", @_ }
sub textfield		{ input_field "input type=text", @_ }
sub textarea		{ input_field "textarea", @_ }
sub hidden		{ input_field "input type=hidden", @_ }
sub checkbox		{ input_field "input type=checkbox", @_ }
sub radio		{ input_field "input type=radio", @_ }

=item mailto_url $mailaddr, key => value, ...

Create a mailto url with the specified headers (see RFC 2368). All
values will be scaped for you. Example:

 mailto_url "pcg@goof.com",
            Subject => "Mail from me",
            body => "(generated from ".referebce_url(1).")";

=cut

sub mailto_url {
   my $url = "mailto:".escape(shift);
   if (@_) {
      $url .= "?";
      for(;;) {
         my $key = shift;
         my $val = shift;
         $url .= $key."=".escape($val);
         last unless @_;
         $url .= "&";
      }
   }
   $url;
}

=item redirect url

=item internal_redirect url

Immediately redirect to the given url. I<These functions do not
return!>. C<redirect_url> creates a http-302 (Page Moved) response,
changign the url the browser sees (and displays). C<internal_redirect>
redirects the request internally (in the web-server), which is faster, but
the browser will not see the url change.

=cut

sub internal_redirect {
   die { internal_redirect => $_[0] };
}

sub redirect {
   $request->status(302);
   $request->header_out(Location => $_[0]);
   $output = "
<html>
<head><title>".__"page redirection"."</title></head>
</head>
<body text=black link=\"#1010C0\" vlink=\"#101080\" alink=red bgcolor=white>
<large>
<a href=\"$_[0]\">
".__"The automatic redirection  has failed. Please try a <i>slightly</i> newer browser next time, and in the meantime <i>please</i> follow this link ;)"."
</a>
</large>
</body>
</html>
";
   die { };
}

my @MON  = qw/Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec/;
my @WDAY = qw/Sun Mon Tue Wed Thu Fri Sat/;

# format can be 'http' (defaut) or 'cookie'
sub unixtime2http {
   my($time, $format) = @_;

   my $sc = $format eq "cookie" ? '-' : ' ';

   my ($sec,$min,$hour,$mday,$mon,$year,$wday) = gmtime $time;

   sprintf "%s, %02d$sc%s$sc%04d %02d:%02d:%02d GMT",
           $WDAY[$wday], $mday, $MON[$mon], $year+1900,
           $hour, $min, $sec;
}

sub set_cookie {
   $request->header_out(
      'Set-Cookie',
      "PAPP_1984="
      . (unpack "h32", $cipher_e->encrypt(pack "VVVV", $userid, 0, 0, rand(1<<30)))
      . "; PATH=/; EXPIRES="
      . unixtime2http($NOW + $cookie_expires, "cookie")
   );
   $state{papp_last_cookie} = $NOW;
   &save_prefs;
}

sub dumpval {
   require Data::Dumper;
   my $d = new Data::Dumper([$_[0]], ["*var"]);
   $d->Terse(1);
   $d->Quotekeys(0);
   #$d->Bless(...);
   $d->Seen($_[1]) if @_ > 1;
   $d->Dump();
}

sub _debugbox {
   my $r;

   my $escape = sub {
      local $_ = shift;
      s/&/&gt;/g;
      s/</&lt;/g;
      s/>/&gt;/g;
      $_;
   };

   my $pre1 = "<font size=7 face=Courier color=black><pre>";
   my $pre0 = "</pre></font>";

   $r .= "UsSA = ($userid,$prevstateid,$stateid,$alternative)<p>\n";

   $r .= "<h3>Debug Output (dprint &amp; friends):</h3>$pre1\n";
   $r .= $escape->($doutput);

   $r .= "$pre0<h3>Input Parameters (%param):</h3>$pre1\n";
   $r .= $escape->(dumpval(\%param));

   $r .= "${pre0}<h3>State (%state):</h3>$pre1\n";
   $r .= $escape->(dumpval(\%state));

   $r .= "$pre0<h3>Module Definition (%\$pmod):</h3>$pre1\n";
   $r .= $escape->(dumpval($pmod,{
            CB     => $pmod->{cb},
            CB_SRC => $pmod->{cb_src},
            MODULE => $pmod->{module},
            IMPORT => $pmod->{import},
         }));

   $r .= "$pre0<h3>Apache->request:</h3>$pre1\n";
   $r .= $escape->($request->as_string);

   $r .= "$pre0\n";

   $r;
}

=item debugbox

Create a small table with a single link "[switch debug mode
ON]". Following that link will enable debugigng mode, reload the current
page and display much more information (%state, %param, %$pmod and the
request parameters). Useful for development. Combined with the admin
package (L<macro/admin>), you can do nice things like in your page:

 #if admin_p
   <: debugbox :>
 #endif

=cut

sub debugbox {
   echo "<br><table bgcolor=\"#e0e0e0\" width=\"95%\" align=center><tr><td><font size=7 face=Helvetica color=black><td id=debugbox>";
   if ($state{papp_debug}) {
      echo "<hr>" . slink("<h1>[switch debug mode OFF]</h1>", papp_debug => 0) . "\n";
      echo _debugbox;
   } else {
      echo "<hr>" . slink("<h1>[switch debug mode ON]</h1>", papp_debug => 1) . "\n";
   }
   echo "</font></td></table>";
}

#############################################################################

sub unescape {
   local $_ = shift;
   y/+/ /;
   s/%([0-9a-fA-F][0-9a-fA-F])/pack "c", hex $1/ge;
   $_;
}

# parse application/x-www-form-urlencoded
sub parse_params {
   for (split /[&;]/, $_[0]) {
      /([^=]+)=(.*)/ and $param{$1} = unescape $2;
   }
}

my %_sql_st;

=item sql_exec "sql-command"[, bind-vals], sql-arg, sql-arg...

Runs the given sql command with the given parameters and returns the
statement handle. The command and the statement handle will be cached, so
prepare will be called only once. If the second argument is an array-ref,
it's contents should be references to variables that get bound via
C<bind_cols>. See the Advantages-section in the DESCRIPTION chapter for an
example.

=cut

sub sql_exec($;@) {
   my $statement = shift;
   my $st = $_sql_st{$statement};
   unless($st) {
      $st = $db->prepare($statement) or fancydie "unable to prepare statement", $statement;
      $_sql_st{$statement} = $st;
   }
   if (ref $_[0]) {
      my $bind = shift;
      $st->execute(@_) or fancydie $db->errstr, "Unable to execute statement `$statement` with ".join(":",@_);
      $st->bind_columns(@$bind) or fancydie $db->errstr, "Unable to bind_columns to statement `$statement` with ".join(":",@_);
   } else {
      $st->execute(@_) or fancydie $db->errstr, "Unable to execute statement `$statement` with ".join(":",@_);
   }
   $st;
}

=item sql_fetch "sql-command", args..

Execute a sql-statement and fetch the first row of results. Depending on
the caller context the row will be returned as a list (array context), or
just the first columns.

=item sql_fetchall "slq-command",  args...

Similarly to C<sql_fetch>, but all result rows will be fetached (this is
inefficient for large results!).

=cut

sub sql_fetch($;@) {
   my $r = &sql_exec->fetchrow_arrayref;
   $r ? wantarray ? @{$r}
                  : $r->[0]
      : ();
}

sub sql_fetchall($;@) {
   my $r = &sql_exec->fetchall_arrayref;
   ref $r && @$r ? @{$r->[0]}==1 ? map @$_,@$r
                                 : @$r
		 : ();
}

=item sql_exists "table where ...", args...

Check wether the result of the sql-statement "select xxx from
$first_argument" would be empty or not.  Works everywhere but can be quite
slow, except on mysql, where this should be quite fast.

=cut

sub sql_exists($;@) {
   sql_fetch("select count(*) from ".shift()." /*! limit 1 */",@_);
}

sub sql_insertid {
   $db->{mysql_insertid};
}

# internal utility function for Gimp::Fu and others
#      talking about code-reuse ^^^^^^^^ ;)
sub wrap_text {
   my $x=$_[0];
   $x=~s/\G(.{1,$_[1]})(\s+|$)/$1\n/gm;
   $x=~s/[ \t\r\n]+$//g;
   $x;
}

#
#   send HTML error page
#   shamelessly stolen from ePerl
#
sub errorpage {
    my ($err, $info) = @_;

    $request->content_type('text/html');
    $request->send_http_header;
    $request->print(<<EOF);
      <html>
      <head>
      <title>phtml: Error</title>
      </head>
      <body bgcolor=\"#d0d0d0\">
      <blockquote>
      <h1>Apache::PApp</h1>
      <b>Version $VERSION</b>

      <p>
      <table bgcolor=\"#d0d0f0\" cellspacing=0 cellpadding=10 border=0>
      <tr>
      <td bgcolor=\"#b0b0d0\">
      <font face=\"Arial, Helvetica\"><b>ERROR:</b></font>
      </td>
      </tr>
      <tr>
      <td>
      <h2><font color=\"#3333cc\">$err</font></h2>
      </td>
      </tr>
      </table>

      <p>
      <table bgcolor=\"#e0e0e0\" cellspacing=0 cellpadding=10 border=0>
      <tr> 
      <td bgcolor=\"#c0c0c0\">
      <font face=\"Arial, Helvetica\"><b>Additional Info:</b></font>
      </td>
      </tr>
      <tr> 
      <td>
      <pre>$info</pre>
      </td> 
      </tr>
      </table>

      <p>
      <table bgcolor=\"#ffc0c0\" cellspacing=0 cellpadding=10 border=0 width="94%">
      <tr> 
      <td bgcolor=\"#e09090\">
      <font face=\"Arial, Helvetica\"><b>Debug Info:</b></font>
      </td>
      </tr>
      <tr> 
      <td>
      ${\_debugbox}
      </td> 
      </tr>
      </table>

      </blockquote>
      </body>
      </html>
EOF
    $request->log_reason("Apache::PApp: $e", $request->uri);
}

=item fancydie $error, $additional_info

Aborts the current page and displays a fancy error box, complete
with backtrace.  C<$error> should be a short error message, while
C<$additional_info> can be a multi-line description of the problem.

=cut

sub fancydie {
   my ($error, $info) = @_;

   $info =~ s/\n*$/\n\n/g;

   require DB;
   @Apache::PApp::DB::ISA = 'DB';
   for my $frame (Apache::PApp::DB->backtrace) {
      $frame =~ s/  +/ /g;
      $frame = wrap_text $frame, 80;
      $frame =~ s/\n/\n     /g;
      $info .= "$frame\n";
   }

   $info .= "\n\n";

   die [$error, $info];
}

=item phtml2perl "pthml-code"

Convert <phtml> code to normal perl. The following four mode-switches are allowed, the initial mode
is ":>" (i.e. plain html).

 <:	start verbatim perl section ("perl-mode")
 :>	start plain html section (non-interpolated html)
 <?	start perl expression (single expr, result will echo'd) (eval this!)
 ?>	start interpolated html section (similar to qq[...]>)

Within plain and interpolated html sections you can also use the
__I<>"string" construct to mark (and map) internationalized text. The
construct must be used verbatim: two underlines, one double-quote, text,
and a trailing double-quote. For more complex uses, just escape to perl
(e.g. <?__I<>"xxx"?>).

=cut

sub phtml2perl {
   my $data = ":>".(shift)."<:";
   my $perl;
   for ($data) {
      /[\x00-\x06]/ and croak "phtml2perl: phtml code contains  illegal control characters (\\x00-\\x06)";
      # could be improved a lot, but this is not timing-critical
      my ($n,$p, $s,$q) = ":";
      for(;;) {
         # PERL
         last unless /\G(.*?)([:?])>/sgc;
         $p = $n; $n = $2;
         if ($1 ne "") {
            if ($p eq ":") {
               $perl .= $1 . ";";
            } else {
               $perl .= '$Apache::PApp::output .= do { ' . $1 . ' }; ';
            }
         }
         # HTML
         last unless /\G(.*?)<([:?])/sgc;
         $p = $n; $n = $2;
         if ($1 ne "") {
            for ($s = $1) {
               # I use \x01 as string-delimiter (it's not whitespace...)
               if ($p eq ":") {
                  $q = "";
                  s/\\/\\\\/g;
               } else {
                  $q = "q";
               }
               # __ "text", use [_]_ so it doesn't get mis-identified by pxgettext ;)
               s/([_]_"(?:(?:[^"\\]+|\\.)*)")/\x01.($1).q$q\x01/g;
               # preprocessor commands
               s/^#\s*if (.*)$/\x01; if ($1) { \$Apache::PApp::output .= q$q\x01/gm;
               s/^#\s*elsif (.*)$/\x01} elsif ($1) { \$Apache::PApp::output .= q$q\x01/gm;
               s/^#\s*else\S*$/\x01} else { \$Apache::PApp::output .= q$q\x01/gm;
               s/^#\s*endif\S*$/\x01} \$Apache::PApp::output .= q$q\x01/gm;
            }
            $perl .= "\$Apache::PApp::output .= q$q\x01$s\x01; ";
         }
      }
      #print "DATA $data\nPERL $perl\n" if $perl =~ /rating/;
   }
   $perl;
}

=item insert_module "module"

Switch permanently module "module". It's output is inserted at the point
of the call to switch_module.

=cut

sub insert_module($) {
   $module = shift;
   $pmod->{module}{$module}{cb}->();
}

=item expand_lang langid, langid...

Tried to identify the closest available language. #fixme#

=cut

sub expand_lang {
   my $lang;
   lang_loop:
   for (@_) {
      $lang = $_; $lang =~ s/^\s+//; $lang =~ s/\s+$//; $lang =~ y/-/_/;
      last if $pmod->{lang}{$lang};
      $lang =~ s/_.*$//;
      last if $pmod->{lang}{$lang};
      for (keys %{$pmod->{lang}}) {
         if (/^${lang}_/) {
            $lang = $_;
            last lang_loop;
         }
      }
   }
   $lang = ${$pmod->{lang}{$lang}} if ref $pmod->{lang}{$lang};
   $lang;
}

my %dbcache;

sub connect_cached {
   my ($dsn, $user, $pass, $flags, $connect) = @_;
   my $id = "$dsn\0$user\0$pass";
   unless ($dbcache{$id} && $dbcache{$id}->ping) {
      $dbcache{$id} = DBI->connect($dsn, $user, $pass, $flags);
      $connect->($dbcache{$id}) if $connect;
   }
   $dbcache{$id};
}

my $stdout;
my $stderr;

my $st_fetchstate;
my $st_newstateid;
my $st_updatestate;

my $st_reload_p;

my $st_fetchprefs;
my $st_newuserid;
my $st_updateprefs;

my $st_updateatime;

=item reload_p

Return the count of reloads, i.e. the number of times this page
was reloaded (which means the session was forked).

This is a relatively costly operation (a database access), so do not do it
by default, but only when you need it.

=cut

sub reload_p {
   if ($prevstateid) {
      $st_reload_p->execute($prevstateid);
      $st_reload_p->fetchrow_arrayref->[0]-1
   } else {
      0;
   }
}

# forcefully read the user-prefs, return new-user-flag
sub get_userprefs {
   my ($prefs, $k, $v);
   $st_fetchprefs->execute($userid);
   if (my ($persistent, $prefs) = $st_fetchprefs->fetchrow_array) {
      $prefs = $prefs ? Storable::thaw lzv1_decompress $prefs : {};

      $state{$k} = $v while ($k,$v) = each %{$prefs->{sys}};
      $state{$k} = $v while ($k,$v) = each %{$prefs->{loc}{$location}};

      $state{persistent_user} = 1 if $persistent;
      1;
   } else {
      undef $userid;
   }
}

=item switch_userid $newuserid

Switch the current session to a new userid. This is useful, for example,
when you do your own user accounting and want a user to log-in. The new
userid must exist, or bad things will happen.

=cut

sub switch_userid {
   my $oldid = $userid;
   $userid = shift;
   if ($userid != $oldid) {
      $state{papp}{switch_olduserid} = $oldid if $oldid;
      if (!$userid) {
         $st_newuserid->execute;
         $userid = $st_newuserid->{mysql_insertid};
         $pmod->{cb}{newuser}->();
         $newuser = 1;
      } else {
         get_userprefs;
      }
      set_cookie; # unconditionally re-set the cookie
   }
}

sub save_prefs {
   my %prefs;

   while (my ($key,$v) = each %state) {
      $prefs{sys}{$key}            = $v if $pmod->{state}{sysprefs}{$key};
      $prefs{loc}{$location}{$key} = $v if $pmod->{state}{preferences}{$key};
   }

   $st_updateprefs->execute($state{persistent_user}*1, lzv1_compress Storable::freeze(\%prefs), $userid);
}

sub update_state {
   $state{save_prefs} = 1 if $newuser;
   $st_updatestate->execute(lzv1_compress Storable::freeze(\%state), $userid, $stateid);
}

#
#   the mod_perl handler
#
sub handler {
   my $r = shift;
   my $state;
   my $filename;

   $NOW = time;

   # create a request object (not sure if needed)
   Apache->request($r);
   $request = $r;

   $stdout = tie *STDOUT, Apache::PApp::FHCatcher;
   $stderr = tie *STDERR, Apache::PApp::FHCatcher;

   *output = $stdout;
   $doutput = "";

   $request->content_type('text/html');

   eval {
      $newuser = 0;

      $statedbh = connect_cached($statedb, "", "", {
         RaiseError => 1,
      }, sub {
         my $dbh = shift;
         $st_fetchstate  = $dbh->prepare("select state, userid, previd from state where id = ?");
         $st_newstateid  = $dbh->prepare("insert into state (previd) values (?)");
         $st_updatestate = $dbh->prepare("update state set state = ?, userid = ? where id = ?");

         $st_reload_p    = $dbh->prepare("select count(*) from state where previd = ?");

         $st_fetchprefs  = $dbh->prepare("select persistent, prefs from user where id = ?");
         $st_newuserid   = $dbh->prepare("insert into user () values ()");
         $st_updateprefs = $dbh->prepare("update user set persistent = ?, prefs = ? where id = ?");
      }) or fancydie "error connecting to papp database", $DBI::errstr;

      # import filename from Apache API
      $location = $request->uri;

      my $pathinfo = $request->path_info;
      $location =~ s/\Q$pathinfo\E$//;

      $pmod = $papp{$location} or do {
         fancydie "Application not mounted", $location;
      };

      if ($checkdeps||1) {#d#
         my @paths = @{$pmod->{paths}};
         my @mtime = @{$pmod->{mtime}};
         while (@paths) {
            my $path = pop @paths;
            my $time = pop @mtime;
            if ((stat $path)[9] > $time) {
               $request->warn("reloading application $location");
               $pmod = $papp{$location} = reload_app $pmod->{paths}[0], $pmod->{config};
               last;
            }
         }
      }

      if ($pmod->{database}) {
         $db = connect_cached(@{$pmod->{database}})
            or fancydie "error connecting to database $pmod->{database}[0]", $DBI::errstr;
      }

      $pathinfo =~ s!^/([^/]*)(?:/([^/]*))?!!;
      my $statehash = $1;
      $module = $2;

      if (32 == length $statehash) {
         ($userid, $prevstateid, $alternative) = unpack "VVVxxxx", $cipher_d->decrypt(pack "h*", $statehash);

         $st_fetchstate->execute($prevstateid);

         my $state = $st_fetchstate->fetchrow_arrayref;

         %state = %{ Storable::thaw lzv1_decompress $state->[0] };

         $nextid = $state->[2];

         if ($state->[1] != $userid) {
            if ($state->[1] != $state{papp}{switch_olduserid}) {
               fancydie "User id mismatch", "maybe someone is tampering?";
            }
         }
         delete $state{papp}{switch_olduserid};

         if ($alternative) {
            %state = (%state, @{$state{papp}{alternative}[$alternative]});
         }
         delete $state{papp}{alternative};

         $module = delete $state{papp_module};

         $st_newstateid->execute($prevstateid);
         $stateid = $st_newstateid->{mysql_insertid};

      } else {
         # woaw, a new session... cool!
         %state = ();

         $module = $statehash if $module eq "";
         $prevstateid = 0;

         if ($request->header_in('Cookie') =~ /PAPP_1984=([0-9a-f]{32,32})/) {
            ($userid, undef, undef) = unpack "VVVxxxx", $cipher_d->decrypt(pack "h*", $1);
         } else {
            undef $userid;
         }

         if ($userid) {
            if (get_userprefs) {
               $state{papp_atime} = $NOW;
               $state{papp_visits}++;
               save_prefs;
            }
         }

         unless ($userid) {
            switch_userid 0;
         }

         $module = "" unless exists $pmod->{module}{$module};
         $module = $pmod->{module}{$module}{nosession};

         $pmod->{cb}{newsession}->();

         $st_newstateid->execute(0);
         $stateid = $st_newstateid->{insertid};
      }

      $state{papp}{module} = $module;

      set_cookie if $state{papp_last_cookie} < $NOW - $cookie_reset;

      # get parameters (GET or POST)
      %param = ($request->args, $request->content);

      # enter any parameters deemed safe (import parameters);
      while (my ($k, $v) = each %param) {
         $state{$k} = $v if $pmod->{state}{import}{$k};
      }
      while (my ($k, $v) = each %{$pmod->{state}{local}}) {
         delete $state{$k} unless exists $v->{$module};
      }

      $alternative = 0;
      
      # WE ARE INITIALIZED
         
      save_prefs if delete $state{save_prefs};

      # find a best-fit for the language
      unless (exists $state{lang}) {
         $state{lang} = expand_lang ((split /,/, @{$request->content_languages}), 'de');
      }
      setmsglang $state{lang};

      $pmod->{cb}{request}->();
      $pmod->{module}{$module}{cb}->();
      $pmod->{cb}{cleanup}->();

      update_state;
   };

   my $e = $@;

   untie *STDOUT; open STDOUT, ">&1";
   untie *STDERR; open STDERR, ">&2";

   if ($e) {
      if ("ARRAY" eq ref $e) {
         errorpage(@{$e});
         return OK;
      } elsif ("HASH" eq ref $e) {
         update_state;
         if ($e->{internal_redirect}) {
            # we have to get rid of the old request (think POST, and Apache->content)
            $request->method_number(M_GET);
            $request->header_in("Content-Type", "");
            $request->internal_redirect($e->{internal_redirect});
            return OK;
         }
      } else {
         errorpage('Script evaluation error', $e);
         return OK;
      }
   } elsif ($$stderr) {
      errorpage('Output on standard error channel', $$stderr);
      return OK;
   }

   $request->header_out('Content-Length', length $$stdout);
   $request->send_http_header;
   $request->print($$stdout) unless $request->header_only;

   return OK;
}

<<'EOF';
#
#   optional Apache::Status information
#
Apache::Status->menu_item(
    'Apache::PApp' => 'Apache::PApp status',
    sub {
        my ($r, $q) = @_;
        push(@s, "<b>Status Information about Apache::PApp</b><br>");
        return \@s;
    }
) if Apache->module('Apache::Status');
EOF

# gather output to a filehandle into a string
package Apache::PApp::FHCatcher;

sub TIEHANDLE {
   my $x;
   bless \$x, shift;
}

sub PRINT {
   my $self = shift;
   $$self .= join "", @_;
   1;
}

sub PRINTF {
   my $self = shift;
   my $fmt = shift; # prototype gotcha!
   $$self .= sprintf $fmt, @_;
   1;
}

sub WRITE {
   my ($self, $data, $length) = @_;
   $$self .= $data;
   $length;
}

package Apache::PApp::papp;

@ISA = 'Exporter';

#sub import {
#   my $class = shift;
#   my $caller = caller;
#   print "ZZ: import($class,$caller)\n";
#   #push @{$caller."::EXPORT"}, @EXPORT;
#   print "ZZ: $class->export_to_level (2, @_)\n";
#   print "ZZ: syms are ",@{"${class}::EXPORT"},"\n";
#   $class->export_to_level(1, @_);
#}

package Apache::PApp::App;

my $upid = "papp000000";

sub compile_in {
   # be careful not to use "my" for global variables -> my vars
   # are visible  within the subs we do!
   my $mod = shift;
   my $sub = eval "package $mod->{package};\n$_[0]\n;";
   if ($@) {
      die $@;#d#
      my $msg = $@;
      ($msg, $data) = @$msg if ref $msg;
      $data =~ s/</&lt;/g;
      $data =~ s/>/&gt;/g;
      $s = 0; $data =~ s/^/sprintf "%03d: ", ++$s/gem;
      send_errorpage($_[0], 'Script compilation error', $msg."<p><p><p>$data");
   }
   $sub;
}

sub compile {
   my $pmod = shift;

   $pmod->{package} = "Apache::PApp::".++$upid;

   @{$pmod->{package}."::EXPORT"} = @{$pmod->{export}};
   @{$pmod->{package}."::ISA"}    = qw(Apache::PApp::papp);

   $pmod->compile_in("use Apache::PApp;");

   for $imp (@{$pmod->{import}}) {
      $pmod->compile_in("BEGIN { import $imp->{package} }");
   }

   # the sort makes sure that module_ is first => fix (tie::IxHash, argh?)
   for my $type (keys %{$pmod->{cb_src}}) {
      $pmod->{cb}{$type} = $pmod->compile_in("sub {\n$pmod->{cb_src}{$type}\n}");
   }

   for my $module (sort keys %{$pmod->{module}}) {
      $pmod->{module}{$module}{cb} = $pmod->compile_in("sub {\n$pmod->{module}{$module}{cb_src}\n}");
   }
}

package Apache::PApp;

use XML::Parser::Expat;

# all modules, prefixed by application name
# all imports, prefixed by IMPORT
my %import;

sub expand_import_path {
   my $module = shift;
   for (@incpath) {
      return "$_/$module"      if -f "$_/$module";
      return "$_/$module.papp" if -f "$_/$module.papp";
   }
   undef;
}

sub load_papp_file {
   my $path = shift;
   my $dmod = shift || "";
   my $pmod = shift || bless {
      import => [],
      cb_src => {
                   init       => "",
                   childinit  => "",
                   childexit  => "",
                   request    => "",
                   cleanup    => "",
                   newsession => "",
                   newuser    => "",
                },
      lang   => {},
      state  => { 
                   import      => { lang => 1 },
                   preferences => { },
                   sysprefs    => {
                                     lang => 1,
                                     papp_atime => 1,
                                     papp_visits => 1,
                                     papp_last_cookie => 1,
                                  },
                },
      @_,
   }, "Apache::PApp::App";

   push @{$pmod->{paths}}, $path;
   push @{$pmod->{mtime}}, (stat $path)[9];

   my $parser = new XML::Parser::Expat(
      Namespaces => 0,
      ErrorContext => 0,
      ParseParamEnt => 0,
      Namespaces => 1,
      ErrorMessage => "Error while parsing file '$path':",
   );

   my @curmod;
   my @curend;
   my @curchr;

   my $lineinfo = sub {
      "\n;\n#line ".($parser->current_line)." \"$path\"\n";
   };

   $parser->setHandlers(
      Char => sub {
         my ($self, $cdata) = @_;
         # convert back to latin1 (from utf8)
         {
            use utf8;
            $cdata =~ tr/\0-\x{ff}//UC;
         }
         $curchr[-1] .= $cdata;
         1;
      },
      End => sub {
         my ($self, $element) = @_;
         my $char = pop @curchr;
         (pop @curend)->($char);
         1;
      },
      Start => sub {
         my ($self, $element, %attr) = @_;
         my $end = sub { };
         push @curchr, "";
         if ($element eq "papp") {
            push @curmod, $dmod;
            $end = sub {
               $pmod->{module}{$dmod}{cb_src} = $_[0];
            };
         } elsif ($element eq "module") {
            defined $attr{name} or $self->xpcroak("<module>: required attribute 'name' not specified");
            $attr{defer} and $self->xpcroak("<module>: defer not yet implemented");
            push @curmod, $attr{name};
            $pmod->{module}{$attr{name}}{nosession}
               = defined $attr{nosession} ? $attr{nosession} : $attr{name};
            if ($attr{src}) {
               my $path = expand_import_path $attr{src};
               $self->xpcroak("<module>: external module '$attr{src}}' not found") unless defined $path;
               load_papp_file($path, $attr{name}, $pmod);
            }
            $end = sub {
               if ($attr{src}) {
                  $self->xpcroak("<module>: no content allowed if src attribute used") if $_[0] !~ /^\s*$/;
               } else {
                  $pmod->{module}{$attr{name}}{cb_src} = $_[0];
               }
               pop @curmod;
            };
         } elsif ($element eq "import") {
            $attr{src} or $self->xpcroak("<import>: required attribute 'src' not specified");
            my $path = expand_import_path $attr{src};
            defined $path or $self->xpcroak("<import>: imported file '$attr{src}' not found");
            my $imp = $import{$path};
            unless (defined $imp) {
               $imp = load_papp_file($path);
               $import{$path} = $imp;
               $imp->compile;
               $imp->{module}{""}{cb}->();
            }
            while (my($k,$v) = each %{$imp->{cb_src}}) {
               $pmod->{cb_src}{$k} .= $v;
            }
            push @{$pmod->{import}}, $imp;
            if ($attr{export} eq "yes") {
               push @{$pmod->{export}}, @{$imp->{export}};
            }
         } elsif ($element eq "macro") {
            defined $attr{name} or $self->xpcroak("<macro>: required attribute 'name' not specified");
            $attr{name} =~ s/(\(.*\))$//;
            my $prototype = $1;
            my $args;
            if ($attr{args}) {
               $args = "my (".(join ",", split /\s+/, $attr{args}).") = \@_;";
            }
            push @{$pmod->{export}}, $attr{name} if $attr{name} =~ s/\*$//;
            $end  = sub {
               $curchr[-1] .= "sub $attr{name}$prototype { $args\n" . $_[0] . "\n}\n";
            };
         } elsif ($element eq "phtml") {
            my $li = &$lineinfo;
            $end = sub {
               $curchr[-1] .= $li . phtml2perl shift;
            };
         } elsif ($element eq "xperl") {
            my $li = &$lineinfo;
            $end = sub {
               my $code = shift;
               $code =~ s{(?<!\w)sub (\w+)\*(?=\W)}{
                  push @{$pmod->{export}}, $1; "sub $1"
               }meg;
               $curchr[-1] .= $li . $code;
            };
         } elsif ($element eq "perl") {
            my $li = &$lineinfo;
            $end = sub {
               $curchr[-1] .= $li . shift;
            };
         } elsif ($element eq "callback") {
            # borken, not really up-to-date
            #$attr{type} =~ /^(init|cleanup|childinit|childexit|newsession|newuser)$/ or $self->xpcroak("<callback>: unknown callback 'type' specified");
            $end = sub {
               $pmod->{cb_src}{$attr{type}} .= shift;
            }
         } elsif ($element eq "state") {
            defined $attr{keys} or $self->xpcroak("<state>: required attribute 'keys' is missing");
            for (split / /, $attr{keys}) {
               $pmod->{state}{preferences}{$_}        = 1 if $attr{preferences} eq "yes";
               $pmod->{state}{sysprefs}{$_}           = 1 if $attr{sysprefs}    eq "yes";
               $pmod->{state}{import}{$_}             = 1 if $attr{import}      eq "yes";
               $pmod->{state}{local}{$_}{$curmod[-1]} = 1 if $attr{local}       eq "yes";
            }
         } elsif ($element eq "database") {
            $pmod->{database} = [
               ($attr{dsn}      || ""),
               ($attr{username} || ""),
               ($attr{password} || ""),
            ];
         } elsif ($element eq "language") {
            defined $attr{lang} or $self->xpcroak("<language>: required attribute 'lang' is missing");
            defined $attr{desc} or $self->xpcroak("<language>: required attribute 'desc' is missing");

            my $lang = $attr{lang};

            $pmod->{lang}{$lang} = $attr{desc};
            for (split / /, $attr{aliases}) {
               $pmod->{lang}{$_} = \$lang;
            }
         } else {
            $self->xpcroak("Element '$element' not recognized");
         }
         push @curend, $end;
         1;
      },
   );

   my $file = do { local(*X,$/); open X, "<", $path or die "$path: $!\n"; <X> };
   unless ($file =~ /^\s*<\?xml\s/) {
      $file = "<?xml version=\"1.0\" encoding=\"iso-8859-1\" standalone=\"no\"?>".
              "<!DOCTYPE papp SYSTEM \"/root/src/Fluffball/papp.dtd\">".
              "<papp>".
              $file.
              "</papp>";
   }

   #print "parsing $path\n";
   $parser->parse($file);
   # workaround for mod_perl bug
   #XML::Parser::Expat::ParseString($parser->{Parser},$file)
   #  or croak $parser->{ErrorMessage};

   $pmod;
}

1;

=back

=head1 SEE ALSO

The C<macro/admin>-package on the distribution, the demo-applications
(.papp-files).

=head1 AUTHOR

 Marc Lehmann <pcg@goof.com>
 http://www.goof.com/pcg/marc/



