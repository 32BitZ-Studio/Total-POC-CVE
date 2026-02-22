<?php
/**
 * The file contains the functions related to currency
 *
 * From handling currency decimals, Currency commas, currency position
 *
 * This file contains important functions for managing currencies in repairBuddy
 * if you are developer you shouldn't edit this file and create your own plugin
 * maintain compatibility. We try to do this as little as possible, but it does
 * in case you want to include new functions or modify existing functions
 * to override a function make sure you do that correctly.
 *
 * @package computer-repair-shop
 * @version 3.7945
 */

defined( 'ABSPATH' ) || exit;

/**
 * Get full list of currency codes.
 *
 * Currency symbols and names should follow the Unicode CLDR recommendation 
 * (https://cldr.unicode.org/translation/currency-names-and-symbols)
 *
 * @return array
 */
if ( ! function_exists( 'wc_cr_get_currencies_array' ) ):
function wc_cr_get_currencies_array() {
	static $currencies;

	if ( ! isset( $currencies ) ) {
		$currencies = array_unique(
				array(
					'AED' => __( 'United Arab Emirates dirham', 'computer-repair-shop' ),
					'AFN' => __( 'Afghan afghani', 'computer-repair-shop' ),
					'ALL' => __( 'Albanian lek', 'computer-repair-shop' ),
					'AMD' => __( 'Armenian dram', 'computer-repair-shop' ),
					'ANG' => __( 'Netherlands Antillean guilder', 'computer-repair-shop' ),
					'AOA' => __( 'Angolan kwanza', 'computer-repair-shop' ),
					'ARS' => __( 'Argentine peso', 'computer-repair-shop' ),
					'AUD' => __( 'Australian dollar', 'computer-repair-shop' ),
					'AWG' => __( 'Aruban florin', 'computer-repair-shop' ),
					'AZN' => __( 'Azerbaijani manat', 'computer-repair-shop' ),
					'BAM' => __( 'Bosnia and Herzegovina convertible mark', 'computer-repair-shop' ),
					'BBD' => __( 'Barbadian dollar', 'computer-repair-shop' ),
					'BDT' => __( 'Bangladeshi taka', 'computer-repair-shop' ),
					'BGN' => __( 'Bulgarian lev', 'computer-repair-shop' ),
					'BHD' => __( 'Bahraini dinar', 'computer-repair-shop' ),
					'BIF' => __( 'Burundian franc', 'computer-repair-shop' ),
					'BMD' => __( 'Bermudian dollar', 'computer-repair-shop' ),
					'BND' => __( 'Brunei dollar', 'computer-repair-shop' ),
					'BOB' => __( 'Bolivian boliviano', 'computer-repair-shop' ),
					'BRL' => __( 'Brazilian real', 'computer-repair-shop' ),
					'BSD' => __( 'Bahamian dollar', 'computer-repair-shop' ),
					'BTC' => __( 'Bitcoin', 'computer-repair-shop' ),
					'BTN' => __( 'Bhutanese ngultrum', 'computer-repair-shop' ),
					'BWP' => __( 'Botswana pula', 'computer-repair-shop' ),
					'BYR' => __( 'Belarusian ruble (old)', 'computer-repair-shop' ),
					'BYN' => __( 'Belarusian ruble', 'computer-repair-shop' ),
					'BZD' => __( 'Belize dollar', 'computer-repair-shop' ),
					'CAD' => __( 'Canadian dollar', 'computer-repair-shop' ),
					'CDF' => __( 'Congolese franc', 'computer-repair-shop' ),
					'CHF' => __( 'Swiss franc', 'computer-repair-shop' ),
					'CLP' => __( 'Chilean peso', 'computer-repair-shop' ),
					'CNY' => __( 'Chinese yuan', 'computer-repair-shop' ),
					'COP' => __( 'Colombian peso', 'computer-repair-shop' ),
					'CRC' => __( 'Costa Rican col&oacute;n', 'computer-repair-shop' ),
					'CUC' => __( 'Cuban convertible peso', 'computer-repair-shop' ),
					'CUP' => __( 'Cuban peso', 'computer-repair-shop' ),
					'CVE' => __( 'Cape Verdean escudo', 'computer-repair-shop' ),
					'CZK' => __( 'Czech koruna', 'computer-repair-shop' ),
					'DJF' => __( 'Djiboutian franc', 'computer-repair-shop' ),
					'DKK' => __( 'Danish krone', 'computer-repair-shop' ),
					'DOP' => __( 'Dominican peso', 'computer-repair-shop' ),
					'DZD' => __( 'Algerian dinar', 'computer-repair-shop' ),
					'EGP' => __( 'Egyptian pound', 'computer-repair-shop' ),
					'ERN' => __( 'Eritrean nakfa', 'computer-repair-shop' ),
					'ETB' => __( 'Ethiopian birr', 'computer-repair-shop' ),
					'EUR' => __( 'Euro', 'computer-repair-shop' ),
					'FJD' => __( 'Fijian dollar', 'computer-repair-shop' ),
					'FKP' => __( 'Falkland Islands pound', 'computer-repair-shop' ),
					'GBP' => __( 'Pound sterling', 'computer-repair-shop' ),
					'GEL' => __( 'Georgian lari', 'computer-repair-shop' ),
					'GGP' => __( 'Guernsey pound', 'computer-repair-shop' ),
					'GHS' => __( 'Ghana cedi', 'computer-repair-shop' ),
					'GIP' => __( 'Gibraltar pound', 'computer-repair-shop' ),
					'GMD' => __( 'Gambian dalasi', 'computer-repair-shop' ),
					'GNF' => __( 'Guinean franc', 'computer-repair-shop' ),
					'GTQ' => __( 'Guatemalan quetzal', 'computer-repair-shop' ),
					'GYD' => __( 'Guyanese dollar', 'computer-repair-shop' ),
					'HKD' => __( 'Hong Kong dollar', 'computer-repair-shop' ),
					'HNL' => __( 'Honduran lempira', 'computer-repair-shop' ),
					'HRK' => __( 'Croatian kuna', 'computer-repair-shop' ),
					'HTG' => __( 'Haitian gourde', 'computer-repair-shop' ),
					'HUF' => __( 'Hungarian forint', 'computer-repair-shop' ),
					'IDR' => __( 'Indonesian rupiah', 'computer-repair-shop' ),
					'ILS' => __( 'Israeli new shekel', 'computer-repair-shop' ),
					'IMP' => __( 'Manx pound', 'computer-repair-shop' ),
					'INR' => __( 'Indian rupee', 'computer-repair-shop' ),
					'IQD' => __( 'Iraqi dinar', 'computer-repair-shop' ),
					'IRR' => __( 'Iranian rial', 'computer-repair-shop' ),
					'IRT' => __( 'Iranian toman', 'computer-repair-shop' ),
					'ISK' => __( 'Icelandic kr&oacute;na', 'computer-repair-shop' ),
					'JEP' => __( 'Jersey pound', 'computer-repair-shop' ),
					'JMD' => __( 'Jamaican dollar', 'computer-repair-shop' ),
					'JOD' => __( 'Jordanian dinar', 'computer-repair-shop' ),
					'JPY' => __( 'Japanese yen', 'computer-repair-shop' ),
					'KES' => __( 'Kenyan shilling', 'computer-repair-shop' ),
					'KGS' => __( 'Kyrgyzstani som', 'computer-repair-shop' ),
					'KHR' => __( 'Cambodian riel', 'computer-repair-shop' ),
					'KMF' => __( 'Comorian franc', 'computer-repair-shop' ),
					'KPW' => __( 'North Korean won', 'computer-repair-shop' ),
					'KRW' => __( 'South Korean won', 'computer-repair-shop' ),
					'KWD' => __( 'Kuwaiti dinar', 'computer-repair-shop' ),
					'KYD' => __( 'Cayman Islands dollar', 'computer-repair-shop' ),
					'KZT' => __( 'Kazakhstani tenge', 'computer-repair-shop' ),
					'LAK' => __( 'Lao kip', 'computer-repair-shop' ),
					'LBP' => __( 'Lebanese pound', 'computer-repair-shop' ),
					'LKR' => __( 'Sri Lankan rupee', 'computer-repair-shop' ),
					'LRD' => __( 'Liberian dollar', 'computer-repair-shop' ),
					'LSL' => __( 'Lesotho loti', 'computer-repair-shop' ),
					'LYD' => __( 'Libyan dinar', 'computer-repair-shop' ),
					'MAD' => __( 'Moroccan dirham', 'computer-repair-shop' ),
					'MDL' => __( 'Moldovan leu', 'computer-repair-shop' ),
					'MGA' => __( 'Malagasy ariary', 'computer-repair-shop' ),
					'MKD' => __( 'Macedonian denar', 'computer-repair-shop' ),
					'MMK' => __( 'Burmese kyat', 'computer-repair-shop' ),
					'MNT' => __( 'Mongolian t&ouml;gr&ouml;g', 'computer-repair-shop' ),
					'MOP' => __( 'Macanese pataca', 'computer-repair-shop' ),
					'MRU' => __( 'Mauritanian ouguiya', 'computer-repair-shop' ),
					'MUR' => __( 'Mauritian rupee', 'computer-repair-shop' ),
					'MVR' => __( 'Maldivian rufiyaa', 'computer-repair-shop' ),
					'MWK' => __( 'Malawian kwacha', 'computer-repair-shop' ),
					'MXN' => __( 'Mexican peso', 'computer-repair-shop' ),
					'MYR' => __( 'Malaysian ringgit', 'computer-repair-shop' ),
					'MZN' => __( 'Mozambican metical', 'computer-repair-shop' ),
					'NAD' => __( 'Namibian dollar', 'computer-repair-shop' ),
					'NGN' => __( 'Nigerian naira', 'computer-repair-shop' ),
					'NIO' => __( 'Nicaraguan c&oacute;rdoba', 'computer-repair-shop' ),
					'NOK' => __( 'Norwegian krone', 'computer-repair-shop' ),
					'NPR' => __( 'Nepalese rupee', 'computer-repair-shop' ),
					'NZD' => __( 'New Zealand dollar', 'computer-repair-shop' ),
					'OMR' => __( 'Omani rial', 'computer-repair-shop' ),
					'PAB' => __( 'Panamanian balboa', 'computer-repair-shop' ),
					'PEN' => __( 'Sol', 'computer-repair-shop' ),
					'PGK' => __( 'Papua New Guinean kina', 'computer-repair-shop' ),
					'PHP' => __( 'Philippine peso', 'computer-repair-shop' ),
					'PKR' => __( 'Pakistani rupee', 'computer-repair-shop' ),
					'PLN' => __( 'Polish z&#x142;oty', 'computer-repair-shop' ),
					'PRB' => __( 'Transnistrian ruble', 'computer-repair-shop' ),
					'PYG' => __( 'Paraguayan guaran&iacute;', 'computer-repair-shop' ),
					'QAR' => __( 'Qatari riyal', 'computer-repair-shop' ),
					'RON' => __( 'Romanian leu', 'computer-repair-shop' ),
					'RSD' => __( 'Serbian dinar', 'computer-repair-shop' ),
					'RUB' => __( 'Russian ruble', 'computer-repair-shop' ),
					'RWF' => __( 'Rwandan franc', 'computer-repair-shop' ),
					'SAR' => __( 'Saudi riyal', 'computer-repair-shop' ),
					'SBD' => __( 'Solomon Islands dollar', 'computer-repair-shop' ),
					'SCR' => __( 'Seychellois rupee', 'computer-repair-shop' ),
					'SDG' => __( 'Sudanese pound', 'computer-repair-shop' ),
					'SEK' => __( 'Swedish krona', 'computer-repair-shop' ),
					'SGD' => __( 'Singapore dollar', 'computer-repair-shop' ),
					'SHP' => __( 'Saint Helena pound', 'computer-repair-shop' ),
					'SLL' => __( 'Sierra Leonean leone', 'computer-repair-shop' ),
					'SOS' => __( 'Somali shilling', 'computer-repair-shop' ),
					'SRD' => __( 'Surinamese dollar', 'computer-repair-shop' ),
					'SSP' => __( 'South Sudanese pound', 'computer-repair-shop' ),
					'STN' => __( 'S&atilde;o Tom&eacute; and Pr&iacute;ncipe dobra', 'computer-repair-shop' ),
					'SYP' => __( 'Syrian pound', 'computer-repair-shop' ),
					'SZL' => __( 'Swazi lilangeni', 'computer-repair-shop' ),
					'THB' => __( 'Thai baht', 'computer-repair-shop' ),
					'TJS' => __( 'Tajikistani somoni', 'computer-repair-shop' ),
					'TMT' => __( 'Turkmenistan manat', 'computer-repair-shop' ),
					'TND' => __( 'Tunisian dinar', 'computer-repair-shop' ),
					'TOP' => __( 'Tongan pa&#x2bb;anga', 'computer-repair-shop' ),
					'TRY' => __( 'Turkish lira', 'computer-repair-shop' ),
					'TTD' => __( 'Trinidad and Tobago dollar', 'computer-repair-shop' ),
					'TWD' => __( 'New Taiwan dollar', 'computer-repair-shop' ),
					'TZS' => __( 'Tanzanian shilling', 'computer-repair-shop' ),
					'UAH' => __( 'Ukrainian hryvnia', 'computer-repair-shop' ),
					'UGX' => __( 'Ugandan shilling', 'computer-repair-shop' ),
					'USD' => __( 'United States (US) dollar', 'computer-repair-shop' ),
					'UYU' => __( 'Uruguayan peso', 'computer-repair-shop' ),
					'UZS' => __( 'Uzbekistani som', 'computer-repair-shop' ),
					'VEF' => __( 'Venezuelan bol&iacute;var', 'computer-repair-shop' ),
					'VES' => __( 'Bol&iacute;var soberano', 'computer-repair-shop' ),
					'VND' => __( 'Vietnamese &#x111;&#x1ed3;ng', 'computer-repair-shop' ),
					'VUV' => __( 'Vanuatu vatu', 'computer-repair-shop' ),
					'WST' => __( 'Samoan t&#x101;l&#x101;', 'computer-repair-shop' ),
					'XAF' => __( 'Central African CFA franc', 'computer-repair-shop' ),
					'XCD' => __( 'East Caribbean dollar', 'computer-repair-shop' ),
					'XOF' => __( 'West African CFA franc', 'computer-repair-shop' ),
					'XPF' => __( 'CFP franc', 'computer-repair-shop' ),
					'YER' => __( 'Yemeni rial', 'computer-repair-shop' ),
					'ZAR' => __( 'South African rand', 'computer-repair-shop' ),
					'ZMW' => __( 'Zambian kwacha', 'computer-repair-shop' ),
				)
		);
	}
	return $currencies;
}
endif;

/**
 * Return the currency symbol by given currency code.
 *
 * Currency symbols and names should follow the Unicode CLDR recommendation 
 * (https://cldr.unicode.org/translation/currency-names-and-symbols)
 *
 * @return array
 */
if ( ! function_exists( 'wc_cr_return_currency_symbol' ) ) :
function wc_cr_return_currency_symbol( $currency_code ) {

	$symbols = array(
		'AED' => '&#x62f;.&#x625;',
		'AFN' => '&#x60b;',
		'ALL' => 'L',
		'AMD' => 'AMD',
		'ANG' => '&fnof;',
		'AOA' => 'Kz',
		'ARS' => '&#36;',
		'AUD' => '&#36;',
		'AWG' => 'Afl.',
		'AZN' => 'AZN',
		'BAM' => 'KM',
		'BBD' => '&#36;',
		'BDT' => '&#2547;&nbsp;',
		'BGN' => '&#1083;&#1074;.',
		'BHD' => '.&#x62f;.&#x628;',
		'BIF' => 'Fr',
		'BMD' => '&#36;',
		'BND' => '&#36;',
		'BOB' => 'Bs.',
		'BRL' => '&#82;&#36;',
		'BSD' => '&#36;',
		'BTC' => '&#3647;',
		'BTN' => 'Nu.',
		'BWP' => 'P',
		'BYR' => 'Br',
		'BYN' => 'Br',
		'BZD' => '&#36;',
		'CAD' => '&#36;',
		'CDF' => 'Fr',
		'CHF' => '&#67;&#72;&#70;',
		'CLP' => '&#36;',
		'CNY' => '&yen;',
		'COP' => '&#36;',
		'CRC' => '&#x20a1;',
		'CUC' => '&#36;',
		'CUP' => '&#36;',
		'CVE' => '&#36;',
		'CZK' => '&#75;&#269;',
		'DJF' => 'Fr',
		'DKK' => 'kr.',
		'DOP' => 'RD&#36;',
		'DZD' => '&#x62f;.&#x62c;',
		'EGP' => 'EGP',
		'ERN' => 'Nfk',
		'ETB' => 'Br',
		'EUR' => '&euro;',
		'FJD' => '&#36;',
		'FKP' => '&pound;',
		'GBP' => '&pound;',
		'GEL' => '&#x20be;',
		'GGP' => '&pound;',
		'GHS' => '&#x20b5;',
		'GIP' => '&pound;',
		'GMD' => 'D',
		'GNF' => 'Fr',
		'GTQ' => 'Q',
		'GYD' => '&#36;',
		'HKD' => '&#36;',
		'HNL' => 'L',
		'HRK' => 'kn',
		'HTG' => 'G',
		'HUF' => '&#70;&#116;',
		'IDR' => 'Rp',
		'ILS' => '&#8362;',
		'IMP' => '&pound;',
		'INR' => '&#8377;',
		'IQD' => '&#x62f;.&#x639;',
		'IRR' => '&#xfdfc;',
		'IRT' => '&#x062A;&#x0648;&#x0645;&#x0627;&#x0646;',
		'ISK' => 'kr.',
		'JEP' => '&pound;',
		'JMD' => '&#36;',
		'JOD' => '&#x62f;.&#x627;',
		'JPY' => '&yen;',
		'KES' => 'KSh',
		'KGS' => '&#x441;&#x43e;&#x43c;',
		'KHR' => '&#x17db;',
		'KMF' => 'Fr',
		'KPW' => '&#x20a9;',
		'KRW' => '&#8361;',
		'KWD' => '&#x62f;.&#x643;',
		'KYD' => '&#36;',
		'KZT' => '&#8376;',
		'LAK' => '&#8365;',
		'LBP' => '&#x644;.&#x644;',
		'LKR' => '&#xdbb;&#xdd4;',
		'LRD' => '&#36;',
		'LSL' => 'L',
		'LYD' => '&#x644;.&#x62f;',
		'MAD' => '&#x62f;.&#x645;.',
		'MDL' => 'MDL',
		'MGA' => 'Ar',
		'MKD' => '&#x434;&#x435;&#x43d;',
		'MMK' => 'Ks',
		'MNT' => '&#x20ae;',
		'MOP' => 'P',
		'MRU' => 'UM',
		'MUR' => '&#x20a8;',
		'MVR' => '.&#x783;',
		'MWK' => 'MK',
		'MXN' => '&#36;',
		'MYR' => '&#82;&#77;',
		'MZN' => 'MT',
		'NAD' => 'N&#36;',
		'NGN' => '&#8358;',
		'NIO' => 'C&#36;',
		'NOK' => '&#107;&#114;',
		'NPR' => '&#8360;',
		'NZD' => '&#36;',
		'OMR' => '&#x631;.&#x639;.',
		'PAB' => 'B/.',
		'PEN' => 'S/',
		'PGK' => 'K',
		'PHP' => '&#8369;',
		'PKR' => '&#8360;',
		'PLN' => '&#122;&#322;',
		'PRB' => '&#x440;.',
		'PYG' => '&#8370;',
		'QAR' => '&#x631;.&#x642;',
		'RMB' => '&yen;',
		'RON' => 'lei',
		'RSD' => '&#1088;&#1089;&#1076;',
		'RUB' => '&#8381;',
		'RWF' => 'Fr',
		'SAR' => '&#x631;.&#x633;',
		'SBD' => '&#36;',
		'SCR' => '&#x20a8;',
		'SDG' => '&#x62c;.&#x633;.',
		'SEK' => '&#107;&#114;',
		'SGD' => '&#36;',
		'SHP' => '&pound;',
		'SLL' => 'Le',
		'SOS' => 'Sh',
		'SRD' => '&#36;',
		'SSP' => '&pound;',
		'STN' => 'Db',
		'SYP' => '&#x644;.&#x633;',
		'SZL' => 'E',
		'THB' => '&#3647;',
		'TJS' => '&#x405;&#x41c;',
		'TMT' => 'm',
		'TND' => '&#x62f;.&#x62a;',
		'TOP' => 'T&#36;',
		'TRY' => '&#8378;',
		'TTD' => '&#36;',
		'TWD' => '&#78;&#84;&#36;',
		'TZS' => 'Sh',
		'UAH' => '&#8372;',
		'UGX' => 'UGX',
		'USD' => '&#36;',
		'UYU' => '&#36;',
		'UZS' => 'UZS',
		'VEF' => 'Bs F',
		'VES' => 'Bs.S',
		'VND' => '&#8363;',
		'VUV' => 'Vt',
		'WST' => 'T',
		'XAF' => 'CFA',
		'XCD' => '&#36;',
		'XOF' => 'CFA',
		'XPF' => 'Fr',
		'YER' => '&#xfdfc;',
		'ZAR' => '&#82;',
		'ZMW' => 'ZK',
	);

	return $symbols[$currency_code];
}
endif;

/**
 * Return currency options
 * Takes array from pre-defined function
 * Takes Selected value 
 * 
 * Returns select options
 */
if ( 'wc_cr_return_currency_options' ) :
	function wc_cr_return_currency_options( $selected_currency ) {
		$selected_currency = ( empty( $selected_currency ) ) ? 'USD' : $selected_currency;

		$currency_array = wc_cr_get_currencies_array();

		$return_options = '';

		if ( ! empty( $currency_array ) && is_array( $currency_array ) ) {
			foreach( $currency_array as $key => $value ) {
				$selected = ( $selected_currency == $key ) ? 'selected' : ''; 
				$return_options .= '<option value="' . $key . '" ' . $selected . '>' . $value . ' (' . wc_cr_return_currency_symbol( $key ) . ')' . '</option>';
			}
		}

		return $return_options;
	}
endif;

/**
 * Return Currency Symbol
 * 
 * No Arugument tages
 * Returns Currency Symbol
 */
if ( ! function_exists( 'return_wc_rb_currency_symbol' ) ) :
	function return_wc_rb_currency_symbol() {
		$wc_cr_selected_currency  = get_option( 'wc_cr_selected_currency' );	
		$wc_cr_selected_currency = ( empty ( $wc_cr_selected_currency ) ) ? 'USD' : $wc_cr_selected_currency;

		$symbol = wc_cr_return_currency_symbol( $wc_cr_selected_currency );
		$symbol = html_entity_decode( $symbol );

		return $symbol;
	}
endif;

/**
 * Currency format input fields
 * Hidden by default
 * JavaScript picks data from these fields. 
 * 
 * And use to fomat currency as per user's selected format.
 */
if ( ! function_exists( 'wc_cr_add_js_fields_for_currency_formating()' ) ) :
function wc_cr_add_js_fields_for_currency_formating() {
	$wc_cr_selected_currency  = get_option( 'wc_cr_selected_currency' );
	$wc_cr_currency_position  = get_option( 'wc_cr_currency_position' );
	$wc_cr_thousand_separator = get_option( 'wc_cr_thousand_separator' );
	$wc_cr_decimal_separator  = get_option( 'wc_cr_decimal_separator' );
	$wc_cr_number_of_decimals = get_option( 'wc_cr_number_of_decimals' );

	$wc_cr_currency_position  = ( empty ( $wc_cr_currency_position ) ) ? 'left' : $wc_cr_currency_position;
	$wc_cr_thousand_separator = ( empty ( $wc_cr_thousand_separator ) ) ? ',' : $wc_cr_thousand_separator;
	$wc_cr_decimal_separator  = ( empty ( $wc_cr_decimal_separator ) ) ? '.' : $wc_cr_decimal_separator;
	$wc_cr_number_of_decimals = ( empty ( $wc_cr_number_of_decimals ) || ! is_numeric ( $wc_cr_number_of_decimals ) ) ? '0' : $wc_cr_number_of_decimals;

	$wc_cr_selected_currency = ( empty ( $wc_cr_selected_currency ) ) ? 'USD' : $wc_cr_selected_currency;

	$symbol = wc_cr_return_currency_symbol( $wc_cr_selected_currency );
	$symbol = html_entity_decode( $symbol );

	$output = '<input type="hidden" id="wc_cr_selected_currency" value="' . $symbol . '" />';
	$output .= '<input type="hidden" id="wc_cr_currency_position" value="' . $wc_cr_currency_position . '" />';
	$output .= '<input type="hidden" id="wc_cr_thousand_separator" value="' . $wc_cr_thousand_separator . '" />';
	$output .= '<input type="hidden" id="wc_cr_decimal_separator" value="' . $wc_cr_decimal_separator . '" />';
	$output .= '<input type="hidden" id="wc_cr_number_of_decimals" value="' . $wc_cr_number_of_decimals . '" />';

	return $output;
}
endif;

/**
 * Format a given value and return the result.
 *
 * @param array $value Value to format.
 * @return array
 */
if ( ! function_exists( 'wc_cr_currency_format' ) ) :
function wc_cr_currency_format( $given_price, $symbol_show = TRUE, $show_comma = TRUE ) {

	//Setup Default Values For Arguments
	$symbol_show = ( ! isset( $symbol_show ) ) ? TRUE : $symbol_show;
	$show_comma  = ( ! isset( $show_comma ) ) ? TRUE : $show_comma;

	$wc_cr_selected_currency  = get_option( 'wc_cr_selected_currency' );
	$wc_cr_currency_position  = get_option( 'wc_cr_currency_position' );
	$wc_cr_thousand_separator = get_option( 'wc_cr_thousand_separator' );
	$wc_cr_decimal_separator  = get_option( 'wc_cr_decimal_separator' );
	$wc_cr_number_of_decimals = get_option( 'wc_cr_number_of_decimals' );

	$wc_cr_currency_position  = ( empty ( $wc_cr_currency_position ) ) ? 'left' : $wc_cr_currency_position;
	$wc_cr_thousand_separator = ( empty ( $wc_cr_thousand_separator ) ) ? ',' : $wc_cr_thousand_separator;
	$wc_cr_decimal_separator  = ( empty ( $wc_cr_decimal_separator ) ) ? '.' : $wc_cr_decimal_separator;
	$wc_cr_number_of_decimals = ( empty ( $wc_cr_number_of_decimals ) || ! is_numeric ( $wc_cr_number_of_decimals ) ) ? '0' : $wc_cr_number_of_decimals;

	$given_price = ( empty( $given_price ) ) ? '0.00' : $given_price;

	$given_price = ( is_numeric( $given_price ) ) ? $given_price : 'NaN';

	if ( $given_price == 'NaN' ) {
		return $given_price;
	}

	$wc_cr_selected_currency = ( empty ( $wc_cr_selected_currency ) ) ? 'USD' : $wc_cr_selected_currency;

	$wc_cr_thousand_separator = ( $show_comma == FALSE ) ? '' : $wc_cr_thousand_separator;
	
	$symbol = wc_cr_return_currency_symbol( $wc_cr_selected_currency );
	$symbol = html_entity_decode( $symbol );

	$given_price = number_format( $given_price, $wc_cr_number_of_decimals, $wc_cr_decimal_separator, $wc_cr_thousand_separator );
	
	$new_price = $given_price;

	switch( $wc_cr_currency_position ) {
		case 'right':
			$new_price = $given_price . $symbol;
			break;
		case 'left_space':
			$new_price = $symbol . ' ' . $given_price;
			break;
		case 'right_space':
			$new_price = $given_price . ' ' . $symbol;
			break;
		default:
			$new_price = $symbol . $given_price;
	}
	return ( $symbol_show == TRUE ) ? $new_price : $given_price;
}
endif;