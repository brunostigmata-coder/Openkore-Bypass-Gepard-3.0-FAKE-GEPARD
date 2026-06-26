package Network::Send::ROla;
use strict;
use base    qw(Network::Send::ServerType0);
use Globals qw($net %config);
use Utils   qw(getTickCount);
use Log     qw(debug);

sub new {
	my ( $class ) = @_;
	my $self = $class->SUPER::new( @_ );

	# ReClassic (cliente RagexeRE 2020-03-04) usa o fluxo de login do kRO Zero,
	# nao o 0C26/0825 do ROla "oficial". Capturado da DLL/cliente:
	#   0x0ACF master_login (senha Rijndael 32B, game_code "0011", flag "G000")
	#   -> 0x0AE3 received_login_token (login_type=0)
	#   -> 0x0064 token_login (SENHA EM TEXTO PLANO, formato classico V Z24 Z24 C)
	# So afeta XKore 0/2; no XKore 1 quem loga e o cliente real.
	my %packets = (
		'0ACF' => [ 'master_login', 'a4 Z25 a32 a5', [qw(game_code username password_rijndael flag)] ],
		'0064' => [ 'token_login',  'V Z24 Z24 C',   [qw(version username password master_version)] ],
		'0436' => [ 'map_login',    'a4 a4 a4 V C',   [qw(accountID charID sessionID tick sex)] ],
		# ReClassic usa 0x00F3 pra public_chat (o ServerType0 manda 0x008C, errado
		# aqui -> o servidor derruba). 'v a*' = len + msg SEM null, igual ao cliente
		# real (captura: f3 00 <len> <msg 32B> = 36 bytes).
		'00F3' => [ 'public_chat',  'v a*',          [qw(len message)] ],
	);

	$self->{packet_list}{$_} = $packets{$_} for keys %packets;

	my %handlers = qw(
		token_login 0064
		actor_action 0437
		actor_info_request 0368
		actor_look_at 0361
		actor_name_request 0369
		buy_bulk_buyer 0819
		buy_bulk_closeShop 0815
		buy_bulk_openShop 0811
		buy_bulk_request 0817
		buy_bulk_vender 0801
		char_create 0A39
		char_delete2_accept 098F
		character_move 035F
		friend_request 0202
		homunculus_command 022D
		item_drop 0363
		item_list_window_selected 07E4
		item_take 0362
		item_use 0439
		map_login 0436
		party_join_request_by_name 02C4
		party_setting 07D7
		pet_capture 019F
		send_equip 0998
		skill_use 0438
		skill_use_location 0366
		storage_item_add 0364
		storage_item_remove 0365
		storage_password 023B
		sync 0360
		public_chat 00F3
		master_login 0ACF
		rodex_open_mailbox 0AC0
		rodex_refresh_maillist 0AC1
	);

	$self->{packet_lut}{$_} = $handlers{$_} for keys %handlers;

	$self->{char_create_version}       = 0x0A39;
	$self->{send_buy_bulk_pack}        = "v V";
	$self->{char_create_version}       = 0x0A39;
	$self->{send_sell_buy_complete}    = 1;
	$self->{send_buy_bulk_market_pack} = "V2";

	# buyer shop
	$self->{buy_bulk_openShop_size}        = "(a10)*";
	$self->{buy_bulk_openShop_size_unpack} = "V v V";

	$self->{buy_bulk_buyer_size}        = "(a8)*";
	$self->{buy_bulk_buyer_size_unpack} = "a2 V v";

	return $self;
}

# 1o passo do login (XKore 0/2): manda 0x0ACF com a senha cifrada em Rijndael
# de 32 bytes, igual ao cliente kRO Zero. game_code "0011" e flag "G000" sao os
# valores capturados do cliente ReClassic.
sub sendMasterLogin {
	my ( $self, $username, $password, $master_version, $version ) = @_;

	my $password_rijndael = $self->encrypt_password( $password );

	my $msg = $self->reconstruct(
		{
			switch            => 'master_login',
			game_code         => '0011',
			username          => $username,
			password_rijndael => $password_rijndael,
			flag              => 'G000',
		}
	);

	$self->sendToServer( $msg );
	debug "Sent ReClassic master_login (0ACF)\n", "sendPacket", 2;
}

# 2o passo: depois do 0x0AE3 (token, login_type=0), reconecta no login server e
# manda 0x0064 com a SENHA EM TEXTO PLANO (formato classico V Z24 Z24 C).
# version=55 e master_version=22 sao os bytes que o cliente real envia (0x37/0x16);
# o master_version do servers.txt (=1) e so controle interno do OpenKore.
sub sendTokenToServer {
	my ( $self, $username, $password, $master_version, $version, $token, $length, $ip, $port ) = @_;

	$net->serverDisconnect();
	$net->serverConnect( $ip, $port );

	my $msg = $self->reconstruct(
		{
			switch         => 'token_login',
			version        => 55,
			username       => $username,
			password       => $password,
			master_version => 22,
		}
	);

	$self->sendToServer( $msg );
	debug "Sent ReClassic token_login (0064)\n", "sendPacket", 2;
}

sub sendMapLogin {
	my ( $self, $accountID, $charID, $sessionID, $sex ) = @_;
	my $msg;
	$sex = 0 if ( $sex > 1 || $sex < 0 );    # Sex can only be 0 (female) or 1 (male)

	# ReClassic: map_login = a4 a4 a4 V C (19 bytes), SEM o campo "unknown"
	# que o ServerType0 padrao usa. Capturado da DLL/cliente.
	my $msg = $self->reconstruct(
		{
			switch    => 'map_login',
			accountID => $accountID,
			charID    => $charID,
			sessionID => $sessionID,
			tick      => getTickCount,
			sex       => $sex,
		}
	);

	$self->sendToServer( $msg );

	debug "Sent sendMapLogin\n", "sendPacket", 2;
}

1;
