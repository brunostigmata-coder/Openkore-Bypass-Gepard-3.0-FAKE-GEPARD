package silenciarEfeito;
use strict;
use Plugins;
use Globals qw(%config);
use Utils qw(existsInList);

# ---------------------------------------------------------------------------
# Silencia mensagens de console por DOMAIN, usando o squelchDomains nativo do
# OpenKore (Log::message poe level=5 se o domain estiver na lista). Sem tocar
# no config.txt. As mensagens "Desconhecido #... utilizou o efeito" usam o
# domain 'effect'. Adicione outros domains em @DOMAINS se quiser.
#
# Reaplica no hook 'pos_load_config.txt' para sobreviver a 'reload config'
# (o reload recarrega o config.txt e zera o squelchDomains).
# ---------------------------------------------------------------------------
my @DOMAINS = ('effect');

Plugins::register('silenciarEfeito', 'Silencia msgs de efeito via squelchDomains', \&unload);
my $hooks = Plugins::addHooks(
	['pos_load_config.txt', \&applySquelch],
);
applySquelch();   # aplica ja no load do plugin

sub applySquelch {
	for my $d (@DOMAINS) {
		next if existsInList($config{squelchDomains} // '', $d);
		$config{squelchDomains} = join(',', grep { length } (($config{squelchDomains} // ''), $d));
	}
}

sub unload {
	Plugins::delHooks($hooks);
	# tira do squelchDomains os domains que este plugin gerencia
	my %rm = map { lc($_) => 1 } @DOMAINS;
	$config{squelchDomains} = join(',',
		grep { length && !$rm{lc($_)} } split(/ *, */, ($config{squelchDomains} // '')));
}

1;
