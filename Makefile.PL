use ExtUtils::MakeMaker;

use 5.006;

WriteMakefile(
    'dist'	=> {
	            PREOP	=> 'chmod -R u=rwX,go=rX . ;',
	            COMPRESS	=> 'gzip -9v',
	            SUFFIX	=> '.gz',
	           },
    'NAME'	=> 'Apache::PApp',
    'VERSION_FROM' => 'PApp.pm',
    'LIBS'	=> [''],
    'DEFINE'	=> '',
    'INC'	=> '',
    'PREREQ_PM'	=> {
                    XML::Parser		=> 2.27,
                    mod_perl		=> 1.21,
                    Storable		=> 0.60,
                    DBI			=> 1.13,
                    DBD::mysql		=> 2.04,
		   },
);

sub MY::postamble {
   my $self=shift;
   
   $MSGFMT = "msgfmt";

   my $postamble = "

datadir = /fluffball
MSGFMT = $MSGFMT

msgmerge:
	./po/update.sh
   
install-po:
";

   print "Portable message object...";
   if ($MSGFMT =~ /./) {
      for (<po/*.po>) {
         my($po)=m!/(.*)\.po$!; #/# for brainy vim
         print " $po";
         $postamble .= "	\$(MKPATH) \$(datadir)/locale/fluffball/LC_MESSAGES\n";
         $postamble .= "	-\$(RM_F) \$(datadir)/locale/fluffball/LC_MESSAGES/$po.mo\n";
         $postamble .= "	-\$(MSGFMT) -o \$(datadir)/locale/fluffball/LC_MESSAGES/$po.mo po/$po.po\n";
         $postamble .= "	-\$(CHMOD) 644 \$(datadir)/locale/fluffball/LC_MESSAGES/$po.mo\n";
      }
   } else {
      print " skipped";
   }
   print "\n";
   
   $postamble;
}
