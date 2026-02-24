<?php
/*========================================================================*\
|| ###################################################################### ||
|| # vBulletin 5.6.0
|| # ------------------------------------------------------------------ # ||
|| # Copyright 2000-2020 MH Sub I, LLC dba vBulletin. All Rights Reserved.  # ||
|| # This file may not be redistributed in whole or significant part.   # ||
|| # ----------------- VBULLETIN IS NOT FREE SOFTWARE ----------------- # ||
|| # http://www.vbulletin.com | http://www.vbulletin.com/license.html   # ||
|| ###################################################################### ||
\*========================================================================*/

abstract class vB5_Frontend_ExplainQueries
{
	public static function isActive()
	{
		return (bool) (vB5_Config::instance()->debug AND isset($_GET['explain']) AND $_GET['explain'] == 1);
	}

	public static function initialize()
	{
		static $initialized = false;

		if (!$initialized AND self::isActive())
		{
			$initialized = true;
			ob_start();
		}
	}

	public static function finish()
	{
		if (self::isActive())
		{
			$data = vB::getDbAssertor()->getDBConnection()->getExplain();

			if (!$data)
			{
				// debug is on in presentation, but not in core
				// display site like normal
				echo ob_get_clean();
				return;
			}
			else
			{
				ob_end_clean();
			}

			header('Content-Type: text/html');
			echo '
			<html>
				<head>
					<title>vBulletin - Explain SQL Queries (' . count($data['explain']) . ')</title>
					<style type="text/css">
					body { background: #EEE; }
					body, p, td, th, h1, h4 { font-family: verdana, sans-serif; font-size: 10pt; text-align: left; }
					.title { margin-bottom: 10px; }
					.query { background: #FFF; border: 1px solid red; margin: 0 0 10px 0; padding: 10px; }
					.query h4 { margin: 0 0 10px 0; }
					.query pre {display:block;overflow:auto;border:1px solid black;margin:0 0 10px 0;padding:10px;background:#F6F6F6;}
					.query pre.trace {height: 30px; cursor: pointer; margin: 10px 0 0 0; background: #FCFCFC;}
					.query ul {padding:0;margin:0;list-style:none;}
					.query table {margin:0 0 10px 0;background:#000;}
					.query table th {background:#F6F6F6;text-align:left;}
					.query table td {background:#FFF;}
					</style>
				</head>
				<body>
					<h1>vBulletin - Explain SQL Queries (' . count($data['explain']) . ')</h1>
			';

			if (!empty($data['describe']))
			{
				echo '<div class="query">';
				echo '<h4>Describe Queries: (Included in the full listing of queries below)</h4><ul>';
				foreach ($data['describe'] as $describe)
				{
					echo '<li>' . htmlspecialchars($describe) . '</li>';
				}
				echo '</ul>';
				echo '</div>';
			}

			if (!empty($data['duplicates']))
			{
				echo '<div class="query">';
				echo '<h4>Duplicate Queries: (Exact textual duplicates, also included in the full listing of queries below)</h4><ul>';
				foreach ($data['duplicates'] as $duplicate)
				{
					echo '<li>Times run: ' . $duplicate['count'] . '<pre>' . htmlspecialchars($duplicate['query']) . '</pre></li>';
				}
				echo '</ul>';
				echo '</div>';
			}

			foreach ($data['explain'] AS $i => $query)
			{
				// add query number for slow & memory intensive displays below
				$data['explain'][$i]['queryNumber'] = $i + 1;

				echo '
				<div class="query">
					<h4><a name="query' . ($i + 1) . '">SQL Query #' . ($i + 1) . '</a></h4>
					<pre>' . htmlspecialchars($query['query']) . '</pre>
					' . $query['explain'] . '
					<ul>
						<li>Time Before: ' . $query['timeStart'] . '</li>
						<li>Time After: ' . $query['timeStop'] . '</li>
						<li>Time Taken: ' . $query['timeTaken'] . '</li>
						<li>Memory Before: ' . $query['memoryStart'] . '</li>
						<li>Memory After: ' . $query['memoryStop'] . '</li>
						<li>Memory Used: ' . $query['memoryUsed'] . '</li>
					</ul>
					<pre class="trace" onclick="this.style.height=\'auto\';this.style.cursor=\'auto\';this.onclick=null;">' . self::formatTrace($query['trace']) . '</pre>
				</div>
				';
			}

			// sort by slowest queries
			usort($data['explain'], function($a, $b)
			{
				if ($a['timeTaken'] == $b['timeTaken'])
				{
					return 0;
				}

				return ($a['timeTaken'] < $b['timeTaken']) ? 1 : -1;
			});

			// display 5 slowest queries
			$limit = 5;
			echo '<h1>5 Slowest Queries</h1><div class="query">';
			foreach ($data['explain'] AS $i => $query)
			{
				echo '
					<div class="title">
						<a href="#query' . $query['queryNumber'] . '">SQL Query #' . $query['queryNumber'] . '</a>
						Time Taken: ' . $query['timeTaken'] . '
						Memory Used: ' . $query['memoryUsed'] . '
					</div>

					<pre>' . htmlspecialchars($query['query']) . '</pre>
				';

				if (!--$limit)
				{
					break;
				}
			}
			echo '</div>';


			$overall = $data['sqltime'] + $data['phptime'];
			echo '<h1>' . count($data['explain']) . ' Queries Run : Total SQL time was ' . number_format($data['sqltime'],6) .
			' seconds , Total PHP time was ' . number_format($data['phptime'],6) . ' seconds , Overall time was ' . number_format($overall,6) . ' seconds.</h1><br />';

			echo '</body></html>';
		}
	}

	protected static function formatTrace(array $trace)
	{
		array_shift($trace);

		$basePath = '';
		foreach ($trace as &$t)
		{
			if (isset($t['file']))
			{
				$t['file'] = str_replace('\\', '/', $t['file']);
				$path = dirname($t['file']);
			}
			else
			{
				$path = '';
			}

			if ($basePath == '' || strlen($path) < strlen($basePath))
			{
				$basePath = $path;
			}

			if (isset($t['args']) && !empty($t['args']))
			{
				$args = array();
				foreach ($t['args'] as $arg)
				{
					$type = gettype($arg);
					switch ($type)
					{
						case 'integer':
						case 'double':
							$argOut = $arg;
							break;
						case 'boolean':
							$argOut = $arg ? 'true' : 'false';
							break;
						case 'string':
							$len = strlen($arg);
							$argOut = "'" . str_replace(array("\r", "\n", "\t"), array('\\r', '\\n', '\\t'), ($len > 20 ? (substr($arg, 0, 10) . "[len:$len]") : $arg)) . "'";
							break;
						case 'object':
							$argOut = get_class($arg);
							break;
						case 'resource':
							$argOut = 'resource[type:' . get_resource_type($arg) . ']';
							break;
						case 'array':
							$argOut = 'array[len:' . count($arg) . ']';
							break;
						default:
							$argOut = $type;
					}
					$args[] = $argOut;
				}
				$t['args'] = $args;
			}

			if (isset($t['object']))
			{
				unset($t['object']);
			}

			unset($t);
		}

		$basePathLen = strlen($basePath);
		$output = array();
		$i = 0;
		foreach ($trace as $t)
		{
			if (isset($t['file']) && strpos($t['file'], $basePath) === 0)
			{
				$t['file'] = substr($t['file'], $basePathLen);
			}

			$t['class'] = isset($t['class']) ? $t['class'] : '';
			$t['type'] = isset($t['type']) ? $t['type'] : '';
			$t['function'] = isset($t['function']) ? $t['function'] : '';
			$t['args2'] = isset($t['args']) ? ('(' . implode(', ', $t['args']) . ')') : '()';
			$t['fileline'] = (isset($t['file']) && $t['file']) ? (' in ' . $t['file'] . '(' . (isset($t['line']) ? $t['line'] : '') . ')') : '';

			$output[] = '#' . $i++ . ' ' . $t['class'] . $t['type'] . $t['function'] . $t['args2'] . $t['fileline'];
		}
		return htmlspecialchars(implode("\n", $output));
	}
}

/*=========================================================================*\
|| #######################################################################
|| # NulleD By - vBSupport.org
|| # CVS: $RCSfile$ - $Revision: 99787 $
|| #######################################################################
\*=========================================================================*/
